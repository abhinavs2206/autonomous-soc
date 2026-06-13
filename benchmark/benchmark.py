"""
GPU vs CPU scoring benchmark.

Runs the IDENTICAL anomaly-scoring kernel on:
  - pandas (CPU)  -- always
  - cuDF   (GPU)  -- only if cuDF + a CUDA device are actually available

It NEVER fabricates a GPU number. On a CPU-only laptop the GPU column reads
"not available on this machine" and the speedup is omitted. Run this on the
NVIDIA/GPU box to get a real GPU column and a real speedup.

Usage:
    python benchmark/benchmark.py            # default 2,000,000 rows
    python benchmark/benchmark.py 500000     # custom row count
"""
import sys, time, random

EXTERNAL_PREFIXES = ("185.", "91.", "45.", "193.")
SENSITIVE_PORTS = [22, 445, 3389, 23, 1433]
SUSPICIOUS_TYPES = {
    "port_scan": 0.55, "brute_force": 0.75, "lateral_move": 0.7,
    "priv_escalation": 0.85, "data_exfil": 0.9, "auth_success": 0.2,
}

_TYPES = list(SUSPICIOUS_TYPES) + ["dns_query", "http_request"]
_IPS = ["185.220.101.12", "91.92.240.3", "10.0.0.5", "10.0.0.20", "10.0.0.32", "8.8.8.8"]
_PORTS = SENSITIVE_PORTS + [53, 80, 443]


def build_rows(n: int):
    random.seed(0)
    return {
        "event_type": [random.choice(_TYPES) for _ in range(n)],
        "src_ip":     [random.choice(_IPS) for _ in range(n)],
        "dst_ip":     [random.choice(_IPS) for _ in range(n)],
        "port":       [random.choice(_PORTS) for _ in range(n)],
    }


def score(df, mod):
    """Backend-agnostic scoring kernel. `mod` is pandas or cudf."""
    n = len(df)
    s = df["event_type"].map(SUSPICIOUS_TYPES).fillna(0.05).astype("float64")
    src = df["src_ip"].astype("str").fillna("")
    dst = df["dst_ip"].astype("str").fillna("")
    ext = mod.Series([False] * n, index=df.index)
    for p in EXTERNAL_PREFIXES:
        ext = ext | src.str.startswith(p) | dst.str.startswith(p)
    s = s + ext.astype("float64") * 0.15
    port = mod.to_numeric(df["port"], errors="coerce").fillna(-1).astype("int64")
    s = s + port.isin(SENSITIVE_PORTS).astype("float64") * 0.10
    s = s.clip(upper=1.0).round(2)
    return int((s >= 0.4).sum())


def time_backend(mod, rows):
    df = mod.DataFrame(rows)
    # warm-up (kernel compile / allocator) so the timed run is representative
    score(df, mod)
    t0 = time.perf_counter()
    flagged = score(df, mod)
    dt = time.perf_counter() - t0
    return dt, flagged


def run_benchmark(n: int) -> dict:
    """Run the benchmark and return structured results. NEVER fabricates a GPU
    number: gpu_ms is null unless cuDF + a CUDA device are actually present."""
    rows = build_rows(n)

    import pandas as pd
    cpu_s, cpu_flagged = time_backend(pd, rows)

    gpu_s = gpu_flagged = gpu_err = None
    try:
        import cudf
        gpu_s, gpu_flagged = time_backend(cudf, rows)
    except Exception as e:
        gpu_err = type(e).__name__

    return {
        "rows": n,
        "cpu_ms": round(cpu_s * 1000, 1),
        "cpu_flagged": cpu_flagged,
        "gpu_ms": round(gpu_s * 1000, 1) if gpu_s else None,
        "gpu_flagged": gpu_flagged,
        "gpu_available": gpu_s is not None,
        "gpu_error": gpu_err,
        "speedup": round(cpu_s / gpu_s, 1) if (gpu_s and gpu_s > 0) else None,
    }


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 2_000_000
    print(f"Benchmarking anomaly scoring on {n:,} rows\n")
    r = run_benchmark(n)
    print(f"  CPU (pandas) : {r['cpu_ms']:8.1f} ms   ({r['cpu_flagged']:,} flagged)")
    if r["gpu_available"]:
        print(f"  GPU (cuDF)   : {r['gpu_ms']:8.1f} ms   ({r['gpu_flagged']:,} flagged)")
    else:
        print(f"  GPU (cuDF)   : not available on this machine  ({r['gpu_error']})")
    print()
    if r["speedup"]:
        print(f"  >>> GPU speedup: {r['speedup']}x faster than CPU")
    else:
        print("  >>> GPU column omitted (no measurement). Run on the GPU box for a real speedup.")


if __name__ == "__main__":
    main()