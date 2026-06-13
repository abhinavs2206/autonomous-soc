import json, random, time, os
from datetime import datetime, timedelta

os.makedirs("data", exist_ok=True)

# A realistic multi-stage attack: recon -> brute force -> lateral -> escalation -> exfil
ATTACK_CHAIN = [
    {"event_type": "port_scan",       "src_ip": "185.220.101.12", "dst_ip": "10.0.0.0/24", "port": 0,    "detail": "Sequential SYN scan across subnet"},
    {"event_type": "brute_force",     "src_ip": "185.220.101.12", "dst_ip": "10.0.0.5",    "port": 22,   "detail": "47 failed SSH auth attempts in 60s"},
    {"event_type": "auth_success",    "src_ip": "185.220.101.12", "dst_ip": "10.0.0.5",    "port": 22,   "detail": "SSH login succeeded for user 'svc_backup'"},
    {"event_type": "lateral_move",    "src_ip": "10.0.0.5",       "dst_ip": "10.0.0.20",   "port": 445,  "detail": "SMB connection to file server, unusual for host"},
    {"event_type": "priv_escalation", "src_ip": "10.0.0.20",      "dst_ip": "10.0.0.1",    "port": 3389, "detail": "RDP to domain controller, new admin token created"},
    {"event_type": "data_exfil",      "src_ip": "10.0.0.20",      "dst_ip": "91.92.240.3", "port": 443,  "detail": "2.3GB outbound to unknown host over TLS"},
]

# Background noise so the attack isn't the only thing in the stream
NOISE = [
    {"event_type": "auth_success", "src_ip": "10.0.0.30", "dst_ip": "10.0.0.5", "port": 22,  "detail": "Routine SSH login"},
    {"event_type": "dns_query",    "src_ip": "10.0.0.31", "dst_ip": "8.8.8.8",  "port": 53,  "detail": "Standard DNS lookup"},
    {"event_type": "http_request", "src_ip": "10.0.0.32", "dst_ip": "10.0.0.40","port": 80,  "detail": "Internal web app access"},
]

def make_event(base, t):
    return {
        "timestamp": t.isoformat() + "Z",
        "host_id": base["dst_ip"],
        **base,
    }

def generate(path="data/logs.jsonl"):
    t = datetime.utcnow()
    events = []
    # interleave noise and the attack chain
    for step in ATTACK_CHAIN:
        for _ in range(random.randint(1, 2)):
            t += timedelta(seconds=random.randint(2, 8))
            events.append(make_event(random.choice(NOISE), t))
        t += timedelta(seconds=random.randint(3, 10))
        events.append(make_event(step, t))

    with open(path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    print(f"Wrote {len(events)} events to {path}")
    return events


def generate_scaled(n=1_000_000, path="data/logs_scaled.jsonl"):
    """Bury the same 6-stage attack chain inside ~n benign noise events.

    This is the scale demo: the GPU scorer reads the whole file and should flag
    exactly the 6 chain events out of n+6. The noise is built from internal IPs
    and benign ports so it stays below the anomaly threshold -- the needles are
    the only things that light up. Nothing is faked: every row is scored for
    real, the chain just genuinely scores higher than the haystack."""
    t = datetime.utcnow()
    # positions to drop the chain events into, spread across the whole stream
    drops = {int((i + 1) * n / (len(ATTACK_CHAIN) + 1)): step
             for i, step in enumerate(ATTACK_CHAIN)}
    written = 0
    with open(path, "w") as f:
        for i in range(n + len(ATTACK_CHAIN)):
            t += timedelta(milliseconds=random.randint(50, 400))
            base = drops.get(i, random.choice(NOISE))
            f.write(json.dumps(make_event(base, t)) + "\n")
            written += 1
    print(f"Wrote {written:,} events ({len(ATTACK_CHAIN)} attack-chain + "
          f"{written - len(ATTACK_CHAIN):,} noise) to {path}")
    return written


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        generate_scaled(int(sys.argv[1]))
    else:
        generate()