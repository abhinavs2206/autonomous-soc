import os, json, re, requests
from dotenv import load_dotenv
from langchain_nvidia_ai_endpoints import ChatNVIDIA
import time

load_dotenv()

# Fast model for classification/drafting; big model only for the final report.
fast_llm = ChatNVIDIA(
    model="meta/llama-3.1-8b-instruct",
    api_key=os.environ["NVIDIA_API_KEY"],
    temperature=0.2, max_tokens=400,
)
report_llm = ChatNVIDIA(
    model="meta/llama-3.1-70b-instruct",
    api_key=os.environ["NVIDIA_API_KEY"],
    temperature=0.3, max_tokens=1024,
)

CATEGORY_MAP = {
    "port_scan": "network", "brute_force": "auth", "auth_success": "auth",
    "lateral_move": "network", "priv_escalation": "endpoint", "data_exfil": "exfiltration",
}

def _invoke(llm, prompt, retries=5):
    """Call the LLM, backing off and retrying on rate-limit (429)."""
    for attempt in range(retries):
        try:
            return llm.invoke(prompt).content
        except Exception as e:
            if "429" in str(e) and attempt < retries - 1:
                wait = 2 ** attempt          # 1s, 2s, 4s, 8s, 16s
                print(f"    rate limited — backing off {wait}s")
                time.sleep(wait)
            else:
                raise

def _json_from_llm(text: str) -> dict:
    text = re.sub(r"```(?:json)?", "", text).strip()
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return {"raw": text}


# AGENT 1: Log Ingestor — deterministic, NO LLM (events are already structured)
def log_ingestor(event: dict) -> dict:
    entities = [v for v in (event.get("src_ip"), event.get("dst_ip")) if v]
    parsed = {
        "summary": event.get("detail", f"{event.get('event_type', 'event')} observed"),
        "entities": entities,
        "category": CATEGORY_MAP.get(event.get("event_type", ""), "other"),
    }
    return {**event, "parsed": parsed}


# AGENT 2: Threat Intel — real NVD API, no LLM
INTEL_MAP = {
    "brute_force":     {"query": "OpenSSH authentication bypass", "technique": "T1110 Brute Force"},
    "lateral_move":    {"query": "SMB remote code execution",     "technique": "T1021 Remote Services"},
    "priv_escalation": {"query": "RDP remote code execution",     "technique": "T1068 Privilege Escalation"},
    "port_scan":       {"query": None, "technique": "T1046 Network Service Scanning"},
    "auth_success":    {"query": None, "technique": "T1078 Valid Accounts"},
    "data_exfil":      {"query": None, "technique": "T1048 Exfiltration Over Alternative Protocol"},
}

def threat_intel(event: dict) -> dict:
    et = event.get("event_type", "")
    m = INTEL_MAP.get(et, {"query": et.replace("_", " "), "technique": "T1059"})
    cves = []
    if m["query"]:
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": m["query"], "resultsPerPage": 3}, timeout=8,
            ).json()
            for v in resp.get("vulnerabilities", [])[:3]:
                cve = v.get("cve", {})
                descs = cve.get("descriptions", [])
                desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                cves.append({"id": cve.get("id"), "desc": desc[:160]})
        except Exception as ex:
            cves = [{"id": None, "desc": f"intel lookup unavailable: {ex}"}]
    return {**event, "threat_intel": {"technique": m["technique"], "cves": cves}}


# AGENT 3: Triage — fast model, short output
def triage(event: dict) -> dict:
    slim = {k: event.get(k) for k in ("event_type", "src_ip", "dst_ip", "port", "anomaly_score", "parsed")}
    prompt = f"""You are a SOC triage analyst. Classify this event.
Event: {json.dumps(slim)}

Note: a SUCCESSFUL authentication from an external IP, especially following failed
attempts, indicates a likely compromise and should be rated HIGH or CRITICAL.

Return ONLY JSON with keys:
severity (CRITICAL|HIGH|MEDIUM|LOW), attack_type, confidence (0-100), reason (one sentence)."""
    return {**event, "triage": _json_from_llm(_invoke(report_llm, prompt))}


# AGENT 4: Response Orchestrator — fast model
def response_agent(event: dict) -> dict:
    prompt = f"""You are an incident responder. Draft a concise response playbook.
Triage: {json.dumps(event.get('triage', {}))}
Summary: {event.get('parsed', {}).get('summary', '')}

Return ONLY JSON with keys:
immediate_actions (list), containment (list), eradication (list), recovery (list).
Keep each list to 2-3 short items."""
    return {**event, "playbook": _json_from_llm(_invoke(fast_llm, prompt))}


# AGENT 5: Report Writer — big model for quality, now includes CVE intel
def report_writer(events: list) -> str:
    flagged = [e for e in events if e.get("flagged")]
    context = [
        {
            "summary": e.get("parsed", {}).get("summary"),
            "severity": e.get("triage", {}).get("severity"),
            "attack_type": e.get("triage", {}).get("attack_type"),
            "anomaly_score": e.get("anomaly_score"),
            "timestamp": e.get("timestamp"),
            "technique": e.get("threat_intel", {}).get("technique"),
            "cves": [c.get("id") for c in e.get("threat_intel", {}).get("cves", []) if c.get("id")],
        }
        for e in flagged
    ]
    prompt = f"""You are a SOC report writer. Write a professional incident report
from these correlated events (they form one attack chain):
{json.dumps(context, indent=2)}

Use these markdown-header sections:
## Executive Summary  (2 sentences)
## Attack Timeline  (chronological bullets)
## Impact Assessment
## Recommended Actions
## Referenced CVEs  (list any CVE IDs from the data; write "None identified" if empty)
## MITRE ATT&CK Techniques  (list the technique per event)
## Audit Trail  (note this was generated autonomously by the agent pipeline)"""
    return _invoke(report_llm, prompt)