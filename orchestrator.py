import json, asyncio, time, uuid, os
from fastapi import FastAPI
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

import morpheus_pipeline
from agents import (
    log_ingestor, threat_intel, triage, review_agent,
    response_agent, report_writer,
)

app = FastAPI(title="Autonomous SOC")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Pre-approval analysis chain (no actions taken yet -- response is gated).
ANALYSIS_CHAIN = [
    ("log_ingestor", log_ingestor),
    ("threat_intel", threat_intel),
    ("triage",       triage),
    ("review",       review_agent),   # debate / second-opinion step
]

# Human-in-the-loop approval state, keyed by run id.
PENDING: dict[str, asyncio.Event] = {}
DECISION: dict[str, str] = {}
APPROVAL_TIMEOUT_S = 300


async def run_analysis_chain(event):
    """Run each analysis agent in a worker thread, timing it. Yields (name, event, ms)."""
    for name, fn in ANALYSIS_CHAIN:
        t0 = time.perf_counter()
        event = await asyncio.to_thread(fn, event)   # agents are network-bound, safe off-thread
        dt = (time.perf_counter() - t0) * 1000
        print(f"    [{name:<14}] {dt/1000:6.2f}s")
        yield name, event, dt


def agents_verdict(processed: list) -> dict:
    """Derive the agent-pipeline verdict from the ACTUAL triage results --
    not hardcoded. If the pipeline triaged multiple stages as HIGH/CRITICAL,
    it has identified the chain."""
    sev = [e.get("triage", {}).get("severity") for e in processed]
    high = [s for s in sev if s in ("HIGH", "CRITICAL")]
    chain = len(high) >= 3
    if chain:
        conf = min(95, 60 + 7 * len(high))
        return {"verdict": "TRUE_POSITIVE", "confidence": conf,
                "summary": f"Correlated {len(high)} high-severity stages into one attack chain.",
                "chain_identified": True}
    if high:
        return {"verdict": "SUSPICIOUS", "confidence": 65,
                "summary": f"Flagged {len(high)} high-severity event(s); chain not fully established.",
                "chain_identified": False}
    return {"verdict": "BENIGN", "confidence": 50,
            "summary": "No high-severity events after triage.", "chain_identified": False}


@app.get("/")
def home():
    return FileResponse("dashboard.html")


@app.get("/benchmark")
async def benchmark(rows: int = 2_000_000):
    """Run the cuDF (GPU) vs pandas (CPU) scoring benchmark and return real
    numbers. gpu_ms is null unless a GPU is actually present -- never faked."""
    rows = max(10_000, min(int(rows), 10_000_000))
    try:
        import importlib.util
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "benchmark", "benchmark.py")
        spec = importlib.util.spec_from_file_location("soc_benchmark", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        result = await asyncio.to_thread(mod.run_benchmark, rows)
        return result
    except Exception as ex:
        import traceback; traceback.print_exc()
        return JSONResponse({"error": f"{type(ex).__name__}: {ex}"}, status_code=500)


@app.post("/approve/{run_id}")
def approve(run_id: str):
    return _decide(run_id, "approved")


@app.post("/reject/{run_id}")
def reject(run_id: str):
    return _decide(run_id, "rejected")


def _decide(run_id: str, decision: str):
    ev = PENDING.get(run_id)
    if ev is None:
        return JSONResponse({"ok": False, "error": "unknown or expired run_id"}, status_code=404)
    DECISION[run_id] = decision
    ev.set()
    return {"ok": True, "run_id": run_id, "decision": decision}


@app.get("/stream")
async def stream(scale: bool = False):
    infile = "data/logs.jsonl" if scale else "data/logs.jsonl"

    async def gen():
        run_id = uuid.uuid4().hex[:12]
        run_start = time.perf_counter()

        yield _sse({"stage": "mode", "scoring_backend": morpheus_pipeline.BACKEND,
                    "run_id": run_id})

        if not os.path.exists(infile):
            hint = ("python log_generator.py 1000000" if scale
                    else "python log_generator.py")
            yield _sse({"stage": "error",
                        "note": f"{infile} not found - generate it first:  {hint}"})
            return

        try:
            # --- Morpheus scoring (GPU if cuDF present, else CPU pandas) ---
            flagged_events, stats = await asyncio.to_thread(morpheus_pipeline.run, infile)
            print(f"[morpheus]  {stats['ms']/1000:.3f}s  ({stats['total']} events, "
                  f"{stats['flagged']} flagged)")

            # One summary instead of one event-per-row -- lets the dashboard run
            # on a million events without choking.
            yield _sse({"stage": "scan_summary", "total": stats["total"],
                        "flagged": stats["flagged"], "backend": stats["backend"],
                        "duration_ms": stats["ms"]})

            # --- Per-event analysis. One failed event must not abort the run. ---
            processed = []
            for event in flagged_events:
                yield _sse({"stage": "morpheus", "event": event,
                            "note": "FLAGGED for analysis", "duration_ms": stats["ms"]})
                print(f"  event: {event.get('event_type')} ({event.get('src_ip')})")
                try:
                    async for name, updated, dt in run_analysis_chain(event):
                        event = updated
                        yield _sse({"stage": name, "event": event, "duration_ms": round(dt, 1)})
                except Exception as ex:
                    print(f"    [agent error] {type(ex).__name__}: {ex}")
                    yield _sse({"stage": "agent_error", "event": event,
                                "note": f"{type(ex).__name__}: {ex}"})
                processed.append(event)

            # --- Human-in-the-loop gate: pause before any response action ---
            ev = asyncio.Event()
            PENDING[run_id] = ev
            yield _sse({"stage": "awaiting_approval", "run_id": run_id,
                        "pending_actions": len(processed),
                        "note": "Response actions require analyst approval."})
            try:
                await asyncio.wait_for(ev.wait(), timeout=APPROVAL_TIMEOUT_S)
                decision = DECISION.get(run_id, "rejected")
            except asyncio.TimeoutError:
                decision = "timeout"
            finally:
                PENDING.pop(run_id, None)
                DECISION.pop(run_id, None)

            if decision != "approved":
                yield _sse({"stage": "halted", "decision": decision,
                            "note": "No response actions executed."})
                return

            # --- Approved: draft response playbooks, then the consolidated report ---
            for event in processed:
                t0 = time.perf_counter()
                event = await asyncio.to_thread(response_agent, event)
                dt = (time.perf_counter() - t0) * 1000
                yield _sse({"stage": "response_agent", "event": event, "duration_ms": round(dt, 1)})

            yield _sse({"stage": "report_writer", "note": "generating report"})
            t0 = time.perf_counter()
            report = await asyncio.to_thread(report_writer, processed)
            report_ms = (time.perf_counter() - t0) * 1000
            total_ms = (time.perf_counter() - run_start) * 1000
            print(f"    [report_writer ] {report_ms/1000:6.2f}s")
            print(f"[TOTAL]     {total_ms/1000:.2f}s")
            yield _sse({"stage": "complete", "report": report,
                        "duration_ms": round(report_ms, 1), "total_ms": round(total_ms, 1)})

        except Exception as ex:
            # Top-level safety net: never leave the dashboard hanging on a half-open
            # stream. Surface the failure so the UI can show it and stop the spinners.
            import traceback; traceback.print_exc()
            PENDING.pop(run_id, None); DECISION.pop(run_id, None)
            yield _sse({"stage": "error",
                        "note": f"stream failed: {type(ex).__name__}: {ex}"})

    return StreamingResponse(gen(), media_type="text/event-stream")


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"