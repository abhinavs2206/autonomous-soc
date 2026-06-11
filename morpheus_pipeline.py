import json
import cudf  # GPU DataFrames (RAPIDS) — ships inside the Morpheus container

# ---- GPU-accelerated behavioral anomaly scorer (cuDF) ----
# Same logic as before, but vectorized across all rows on the GPU.
EXTERNAL_PREFIXES = ("185.", "91.", "45.", "193.")
SENSITIVE_PORTS = [22, 445, 3389, 23, 1433]
SUSPICIOUS_TYPES = {
    "port_scan": 0.55, "brute_force": 0.75, "lateral_move": 0.7,
    "priv_escalation": 0.85, "data_exfil": 0.9, "auth_success": 0.2,
}


def run(infile="data/logs.jsonl", outfile="data/scored_events.jsonl", threshold=0.4):
    # 1. Load the whole log file straight onto the GPU
    df = cudf.read_json(infile, lines=True)
    n = len(df)

    # 2. Base score from event type (vectorized GPU map)
    score = df["event_type"].map(SUSPICIOUS_TYPES).fillna(0.05).astype("float64")

    # 3. External-IP bump — OR across prefixes, all on GPU
    src = df["src_ip"].astype("str").fillna("")
    dst = df["dst_ip"].astype("str").fillna("")
    ext = cudf.Series([False] * n, index=df.index)
    for p in EXTERNAL_PREFIXES:
        ext = ext | src.str.startswith(p) | dst.str.startswith(p)
    score = score + ext.astype("float64") * 0.15

    # 4. Sensitive-port bump
    port = cudf.to_numeric(df["port"], errors="coerce").fillna(-1).astype("int64")
    sens = port.isin(SENSITIVE_PORTS)
    score = score + sens.astype("float64") * 0.10

    # 5. Clamp, round, flag
    score = score.clip(upper=1.0).round(2)
    df["anomaly_score"] = score
    df["flagged"] = score >= threshold

    # 6. Write scored events back out (same JSONL format as before)
    df.to_json(outfile, orient="records", lines=True)

    flagged = int(df["flagged"].sum())
    print(f"Scored {n} events on GPU, flagged {flagged} as anomalous")

    with open(outfile) as f:
        return [json.loads(line) for line in f if line.strip()]

if __name__ == "__main__":
    run()