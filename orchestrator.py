import json, asyncio, time
from fastapi import FastAPI
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

import morpheus_pipeline
from agents import (
    log_ingestor, threat_intel, triage, response_agent, report_writer,
)

app = FastAPI(title="Autonomous SOC")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

AGENT_CHAIN = [
    ("log_ingestor",   log_ingestor),
    ("threat_intel",   threat_intel),
    ("triage",         triage),
    ("response_agent", response_agent),
]


async def run_agent_chain(event):
    """Run each agent in a worker thread, timing it. Yields (name, event, ms)."""
    for name, fn in AGENT_CHAIN:
        t0 = time.perf_counter()
        event = await asyncio.to_thread(fn, event)   # agents are network-bound, safe off-thread
        dt = (time.perf_counter() - t0) * 1000
        print(f"    [{name:<14}] {dt/1000:6.2f}s")
        yield name, event, dt


@app.get("/")
def home():
    return FileResponse("dashboard.html")


@app.get("/stream")
async def stream():
    async def gen():
        run_start = time.perf_counter()

        # --- Morpheus GPU scoring (kept inline: fast, avoids cross-thread CUDA) ---
        t0 = time.perf_counter()
        scored = morpheus_pipeline.run()
        morpheus_ms = (time.perf_counter() - t0) * 1000
        print(f"\n[morpheus]  {morpheus_ms/1000:.3f}s  ({len(scored)} events)")

        processed = []
        for event in scored:
            if not event.get("flagged"):
                yield _sse({"stage": "morpheus", "event": event,
                            "note": "below threshold", "duration_ms": round(morpheus_ms, 1)})
                continue

            yield _sse({"stage": "morpheus", "event": event,
                        "note": "FLAGGED for analysis", "duration_ms": round(morpheus_ms, 1)})

            print(f"  event: {event.get('event_type')} ({event.get('src_ip')})")
            async for name, updated, dt in run_agent_chain(event):
                event = updated
                yield _sse({"stage": name, "event": event, "duration_ms": round(dt, 1)})
            processed.append(event)

        # --- Final consolidated report ---
        yield _sse({"stage": "report_writer", "note": "generating report"})
        t0 = time.perf_counter()
        report = await asyncio.to_thread(report_writer, processed)
        report_ms = (time.perf_counter() - t0) * 1000
        total_ms = (time.perf_counter() - run_start) * 1000
        print(f"    [report_writer ] {report_ms/1000:6.2f}s")
        print(f"[TOTAL]     {total_ms/1000:.2f}s\n")

        yield _sse({"stage": "complete", "report": report,
                    "duration_ms": round(report_ms, 1), "total_ms": round(total_ms, 1)})

    return StreamingResponse(gen(), media_type="text/event-stream")


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"