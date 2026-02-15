"""
ShadowGuard - mitmproxy Addon
Intercepts HTTPS traffic to AI services and detects PHI.

Usage:
    mitmdump -s shadowguard_addon.py --listen-port 8080
"""

import mitmproxy.http
from mitmproxy import ctx
import json
import re
import time
import urllib.request
import threading
from datetime import datetime

# Import the PHI redactor
from phi_redactor import PHIRedactor


# ============================================================
# CONFIGURATION
# ============================================================

# Known AI service domains → friendly names
AI_DOMAINS = {
    # OpenAI
    "api.openai.com": "OpenAI API",
    "chat.openai.com": "ChatGPT",
    "chatgpt.com": "ChatGPT",
    "cdn.oaistatic.com": "OpenAI Static",
    # Anthropic
    "api.anthropic.com": "Anthropic API",
    "claude.ai": "Claude",
    # Google
    "generativelanguage.googleapis.com": "Gemini API",
    "gemini.google.com": "Gemini",
    "bard.google.com": "Bard",
    # Others
    "chat.deepseek.com": "DeepSeek",
    "api.cohere.ai": "Cohere",
    "api.perplexity.ai": "Perplexity",
    "api-inference.huggingface.co": "HuggingFace",
    "api.mistral.ai": "Mistral",
    "api.together.xyz": "Together AI",
    "api.groq.com": "Groq",
    "copilot.microsoft.com": "MS Copilot",
}

# Domains to ignore (static assets, telemetry, etc.)
IGNORE_PATHS = {
    "/v1/models",  # Just listing models, not sending data
    "/favicon.ico",
    "/_next/",
    "/assets/",
}

# PHI detection patterns
PHI_PATTERNS = {
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "MRN": r"\bMRN[\s:#]*\d{5,}\b",
    "Phone": r"\b\d{3}[-.)]\s*\d{3}[-.)]\s*\d{4}\b",
    "DOB": r"\b(?:DOB|date\s*of\s*birth)[\s:]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
    "Patient_Name": r"\b(?:patient|pt|name)[\s:]+[A-Z][a-z]+\s+[A-Z][a-z]+\b",
    "Diagnosis_Code": r"\b[A-Z]\d{2}\.?\d{0,4}\b",  # ICD-10 codes like E11.9
    "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "Address": r"\b\d{1,5}\s+[A-Z][a-z]+\s+(?:St|Ave|Blvd|Dr|Rd|Ln|Way)\b",
}

# Medical keywords that boost risk score
MEDICAL_KEYWORDS = [
    "patient",
    "diagnosis",
    "prescribed",
    "medication",
    "discharge",
    "admission",
    "lab results",
    "radiology",
    "MRI",
    "CT scan",
    "blood pressure",
    "heart rate",
    "allergies",
    "surgery",
    "prognosis",
    "treatment plan",
    "medical record",
    "clinical notes",
    "HIPAA",
    "PHI",
    "EHR",
    "ICD",
    "CPT",
    "vital signs",
]


# ============================================================
# RISK SCORING
# ============================================================


def detect_phi(text: str) -> dict:
    """Scan text for PHI patterns. Returns dict of pattern_name → matches."""
    findings = {}
    for name, pattern in PHI_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            findings[name] = matches
    return findings


def count_medical_keywords(text: str) -> int:
    """Count how many medical keywords appear in the text."""
    text_lower = text.lower()
    return sum(1 for kw in MEDICAL_KEYWORDS if kw.lower() in text_lower)


def score_risk(body: str, service: str, method: str) -> dict:
    """
    Score the risk of a request on a 0-100 scale.
    Returns a dict with score, breakdown, and PHI findings.
    """
    score = 0
    reasons = []

    # Base score: any request to unauthorized AI service
    score += 15
    reasons.append(f"Unauthorized AI service: {service} (+15)")

    # PHI detection (biggest signal)
    phi = detect_phi(body)
    if phi:
        phi_boost = min(len(phi) * 15, 45)  # up to +45
        score += phi_boost
        for ptype, matches in phi.items():
            reasons.append(f"PHI detected [{ptype}]: {len(matches)} match(es) (+15)")

    # Medical keyword density
    med_count = count_medical_keywords(body)
    if med_count >= 3:
        med_boost = min(med_count * 3, 15)
        score += med_boost
        reasons.append(f"Medical keywords: {med_count} found (+{med_boost})")

    # Payload size (large = likely pasting documents)
    body_len = len(body)
    if body_len > 10000:
        score += 15
        reasons.append(f"Very large payload: {body_len} chars (+15)")
    elif body_len > 3000:
        score += 8
        reasons.append(f"Large payload: {body_len} chars (+8)")

    # POST/PUT = sending data (vs GET = just browsing)
    if method in ("POST", "PUT", "PATCH"):
        score += 5
        reasons.append(f"Data submission method: {method} (+5)")

    # Time-based risk (off-hours)
    hour = time.localtime().tm_hour
    if hour < 6 or hour > 22:
        score += 5
        reasons.append(f"Off-hours access: {hour}:00 (+5)")

    return {
        "score": min(score, 100),
        "reasons": reasons,
        "phi_findings": {k: len(v) for k, v in phi.items()},
        "phi_detected": len(phi) > 0,
        "medical_keyword_count": med_count,
        "payload_size": body_len,
    }


# ============================================================
# PRETTY PRINTING
# ============================================================


def risk_color(score: int) -> str:
    if score >= 70:
        return "\033[91m"  # red
    elif score >= 40:
        return "\033[93m"  # yellow
    else:
        return "\033[92m"  # green


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def print_event(flow, service, risk, body):
    """Pretty-print a detected event to the terminal."""
    color = risk_color(risk["score"])
    ts = datetime.now().strftime("%H:%M:%S")

    print(f"\n{'=' * 70}")
    print(f"{BOLD}🛡️  SHADOWGUARD INTERCEPT{RESET}")
    print(f"{'=' * 70}")
    print(f"  ⏰ Time:      {ts}")
    print(f"  🌐 Service:   {service}")
    print(f"  📡 Method:    {flow.request.method} {flow.request.path}")
    print(f"  📦 Size:      {len(body)} chars")
    print(f"  {color}{BOLD}⚠️  Risk Score: {risk['score']}/100{RESET}")

    if risk["phi_detected"]:
        print(f"  {BOLD}\033[91m🚨 PHI DETECTED:{RESET}")
        for ptype, count in risk["phi_findings"].items():
            print(f"     - {ptype}: {count} match(es)")

    if risk["reasons"]:
        print(f"  📋 Breakdown:")
        for reason in risk["reasons"]:
            print(f"     • {reason}")

    if risk["score"] > 70:
        print(f"\n  {BOLD}\033[91m🚫 ACTION: REQUEST BLOCKED{RESET}")
        print(f"  → User redirected to Safe Zone")
    elif risk["score"] > 40:
        print(f"\n  {BOLD}\033[93m⚠️  ACTION: WARNING ISSUED{RESET}")
    else:
        print(f"\n  {BOLD}\033[92m📝 ACTION: LOGGED ONLY{RESET}")

    # Preview the body (show the full user message)
    if body and len(body.strip()) > 0:
        print(f"\n  💬 {BOLD}USER MESSAGE:{RESET}")
        print(f"  ┌{'─' * 56}┐")
        # Show up to 1000 chars, wrap lines
        preview = body[:1000]
        for line in preview.split("\n"):
            while len(line) > 54:
                print(f"  │ {line[:54]} │")
                line = line[54:]
            print(f"  │ {line:<54} │")
        if len(body) > 1000:
            print(f"  │ {'... (truncated)':<54} │")
        print(f"  └{'─' * 56}┘")

    print(f"{'=' * 70}\n")


# ============================================================
# MITMPROXY ADDON
# ============================================================


BACKEND_URL = "http://localhost:8000/api/events"


class ShadowGuard:
    def __init__(self):
        self.redactor = PHIRedactor(use_presidio=False)
        ctx.log.info("ShadowGuard initialized with PHI redactor")

    def _post_event(self, flow, matched_service, risk, phi_result, readable_body, action):
        """Post event to the FastAPI backend (non-blocking)."""
        event = {
            "source_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "unknown",
            "user_agent": flow.request.headers.get("User-Agent", "")[:200],
            "ai_service": matched_service,
            "request_method": flow.request.method,
            "request_path": flow.request.path[:500],
            "risk_score": risk["score"],
            "severity": (
                "critical" if risk["score"] > 70
                else "high" if risk["score"] > 50
                else "medium" if risk["score"] > 30
                else "low" if risk["score"] > 10
                else "clean"
            ),
            "phi_detected": phi_result["phi_detected"],
            "phi_count": phi_result["phi_count"],
            "phi_types": phi_result.get("entity_types_found", []),
            "phi_findings": phi_result.get("findings", []),
            "original_text": readable_body[:2000],
            "redacted_text": phi_result.get("redacted_text", "")[:2000] if phi_result["phi_detected"] else None,
            "action": action,
            "engine": phi_result.get("engine", "unknown"),
        }

        def _send():
            try:
                data = json.dumps(event).encode("utf-8")
                req = urllib.request.Request(
                    BACKEND_URL,
                    data=data,
                    headers={"Content-Type": "application/json"},
                )
                urllib.request.urlopen(req, timeout=2)
            except Exception:
                pass  # Don't crash the proxy if backend is down

        threading.Thread(target=_send, daemon=True).start()

    def request(self, flow: mitmproxy.http.HTTPFlow):
        host = flow.request.pretty_host

        # Check if this is an AI service
        matched_service = None
        for domain, service in AI_DOMAINS.items():
            if domain in host:
                matched_service = service
                break

        if not matched_service:
            return  # Not an AI service, let it through

        # Skip static assets and non-interesting paths
        path = flow.request.path
        if any(ignore in path for ignore in IGNORE_PATHS):
            return

        # Extract the request body
        raw_body = flow.request.get_text() or ""

        # If the body is JSON, extract the actual user message
        readable_body = raw_body
        try:
            parsed = json.loads(raw_body)

            # ChatGPT web app format
            if "action" in parsed and "messages" in parsed:
                parts = []
                for m in parsed["messages"]:
                    content = m.get("content", {})
                    if isinstance(content, dict) and "parts" in content:
                        for part in content["parts"]:
                            if isinstance(part, str):
                                parts.append(part)
                    elif isinstance(content, str):
                        parts.append(content)
                if parts:
                    readable_body = "\n".join(parts)

            # OpenAI API format
            elif "messages" in parsed:
                readable_body = "\n".join(
                    m.get("content", "")
                    for m in parsed["messages"]
                    if isinstance(m.get("content"), str)
                )

            # Anthropic API format
            elif "prompt" in parsed:
                readable_body = parsed["prompt"]

        except (json.JSONDecodeError, TypeError):
            pass

        # ── PHI Detection & Redaction via Presidio ─────────────────
        phi_result = self.redactor.analyze_and_redact(readable_body)

        # Score the risk (uses regex internally for keywords/size)
        risk = score_risk(readable_body, matched_service, flow.request.method)
        # Override PHI findings with Presidio results (more accurate)
        risk["phi_detected"] = phi_result["phi_detected"]
        risk["phi_count"] = phi_result["phi_count"]
        risk["phi_findings"] = {}
        for f in phi_result["findings"]:
            etype = f["entity_type"]
            risk["phi_findings"][etype] = risk["phi_findings"].get(etype, 0) + 1
        # Boost score based on Presidio entity count
        if phi_result["phi_detected"]:
            risk["score"] = min(
                risk["score"] + len(phi_result["entity_types_found"]) * 12, 100
            )

        # Print the intercept event
        print_event(flow, matched_service, risk, readable_body)

        # ── Action: Redact & Forward ──────────────────────────────
        if phi_result["phi_detected"]:
            redacted_text = phi_result["redacted_text"]

            # Show redaction details in terminal
            print(f"\n  {'=' * 56}")
            print(f"  ✂️  {BOLD}PHI REDACTION APPLIED ({phi_result['engine']}){RESET}")
            print(f"  {'=' * 56}")
            for f in phi_result["findings"]:
                print(f'    🔴 {f["entity_type"]}: "{f["text"]}" → [REDACTED]')
            print(f"\n  📝 {BOLD}REDACTED MESSAGE:{RESET}")
            print(f"  ┌{'─' * 56}┐")
            for line in redacted_text[:600].split("\n"):
                while len(line) > 54:
                    print(f"  │ {line[:54]} │")
                    line = line[54:]
                print(f"  │ {line:<54} │")
            print(f"  └{'─' * 56}┘")
            print(
                f"\n  ✅ {BOLD}\033[92mForwarding REDACTED request to {matched_service}{RESET}"
            )
            print(f"  {'=' * 56}\n")

            # Rewrite the request body with redacted content
            try:
                original_json = json.loads(raw_body)
                modified_json = self._replace_content(original_json, redacted_text)
                flow.request.set_text(json.dumps(modified_json))
            except (json.JSONDecodeError, TypeError) as e:
                ctx.log.warn(f"Could not rewrite JSON body: {e}")

            # Tag headers
            flow.request.headers["X-ShadowGuard"] = "redacted"
            flow.request.headers["X-ShadowGuard-Risk"] = str(risk["score"])
            flow.request.headers["X-ShadowGuard-PHI-Count"] = str(
                phi_result["phi_count"]
            )

            # Post to backend
            self._post_event(flow, matched_service, risk, phi_result, readable_body, "redacted")

        else:
            # No PHI — clean pass-through
            print(f"\n  ✅ {BOLD}\033[92mNo PHI — passing through cleanly{RESET}\n")
            flow.request.headers["X-ShadowGuard"] = "clean"
            flow.request.headers["X-ShadowGuard-Risk"] = str(risk["score"])

            # Post to backend
            self._post_event(flow, matched_service, risk, phi_result, readable_body, "clean")

    def _replace_content(self, payload: dict, new_content: str) -> dict:
        """Replace the user message in the API payload with redacted version."""

        # ChatGPT web format
        if "action" in payload and "messages" in payload:
            for msg in payload["messages"]:
                content = msg.get("content", {})
                if isinstance(content, dict) and "parts" in content:
                    content["parts"] = [new_content]

        # OpenAI API format
        elif "messages" in payload:
            for msg in payload["messages"]:
                if msg.get("role") == "user":
                    msg["content"] = new_content

        # Anthropic format
        elif "prompt" in payload:
            payload["prompt"] = new_content

        return payload


addons = [ShadowGuard()]
