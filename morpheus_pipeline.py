import json, time
import cudf as xp  # GPU DataFrames (RAPIDS) -- ships inside the Morpheus container

BACKEND = "cuDF (GPU)"

# ---- GPU-accelerated behavioral anomaly scorer (cuDF) ----
EXTERNAL_PREFIXES = ("185.", "91.", "45.", "193.")
SENSITIVE_PORTS = [22, 445, 3389, 23, 1433]
SUSPICIOUS_TYPES = {
    "port_scan": 0.55, "brute_force": 0.75, "lateral_move": 0.7,
    "priv_escalation": 0.85, "data_exfil": 0.9, "auth_success": 0.2,
}


def score_frame(df):
    """Vectorized anomaly score over a dataframe (cuDF or pandas). Mutates and
    returns df with 'anomaly_score' and 'flagged' columns added."""
    n = len(df)

    # 1. Base score from event type
    score = df["event_type"].map(SUSPICIOUS_TYPES).fillna(0.05).astype("float64")

    # 2. External-IP bump -- OR across known-bad prefixes
    src = df["src_ip"].astype("str").fillna("")
    dst = df["dst_ip"].astype("str").fillna("")
    ext = xp.Series([False] * n, index=df.index)
    for p in EXTERNAL_PREFIXES:
        ext = ext | src.str.startswith(p) | dst.str.startswith(p)
    score = score + ext.astype("float64") * 0.15

    # 3. Sensitive-port bump
    port = xp.to_numeric(df["port"], errors="coerce").fillna(-1).astype("int64")
    sens = port.isin(SENSITIVE_PORTS)
    score = score + sens.astype("float64") * 0.10

    # 4. Clamp, round, flag
    score = score.clip(upper=1.0).round(2)
    df["anomaly_score"] = score
    return df


def run(infile="data/logs.jsonl", threshold=0.4):
    """Score every event in `infile`. Returns (flagged_events, stats).

    Only the flagged rows are pulled back into Python -- at a million events the
    other 999,994 never leave the dataframe, so this scales without flooding the
    orchestrator or the browser. stats carries the headline scale numbers."""
    t0 = time.perf_counter()
    df = xp.read_json(infile, lines=True)
    n = len(df)

    df = score_frame(df)
    df["flagged"] = df["anomaly_score"] >= threshold

    # Pull the tiny flagged subset back to the host WITHOUT going through numba's
    # CUDA array interface (which .to_pandas() uses, and which fails in some
    # Morpheus containers where numba can't enumerate the device even though
    # libcudf can). to_arrow() / to_json() are pure libcudf paths.
    sub = df[df["flagged"]].reset_index(drop=True)
    try:
        flagged = sub.to_arrow().to_pylist()                 # libcudf -> Arrow (host)
    except Exception:
        flagged = json.loads(sub.to_json(orient="records"))  # libcudf JSON writer fallback

    ms = (time.perf_counter() - t0) * 1000
    stats = {"total": int(n), "flagged": len(flagged), "backend": BACKEND, "ms": round(ms, 1)}
    print(f"[{BACKEND}] scored {n:,} events in {ms:.1f} ms, flagged {len(flagged)} as anomalous")
    return flagged, stats


if __name__ == "__main__":
    import sys
    infile = sys.argv[1] if len(sys.argv) > 1 else "data/logs.jsonl"
    flagged, stats = run(infile)
    print(f"  scanned {stats['total']:,} on {stats['backend']} -> {stats['flagged']} flagged")
    for e in flagged:
        print(f"    {e.get('event_type'):<16} score={e.get('anomaly_score')}  {e.get('src_ip')}")