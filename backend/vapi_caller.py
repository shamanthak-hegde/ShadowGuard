"""
VAPI Voice Call integration for ShadowGuard.
Triggers automated phone calls for high-risk PHI exposure events
using a pre-configured VAPI assistant with GPT-5.2 + ElevenLabs.
"""

import os
import ssl
import threading
import logging
from datetime import datetime, timezone, timedelta
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import json

from database import get_cursor, dict_cursor

logger = logging.getLogger("shadowguard.vapi")

# ── Configuration ──────────────────────────────────────────
VAPI_ENABLED = os.getenv("VAPI_ENABLED", "false").lower() == "true"
VAPI_API_KEY = os.getenv("VAPI_API_KEY", "")
VAPI_PHONE_NUMBER_ID = os.getenv("VAPI_PHONE_NUMBER_ID", "")
VAPI_ASSISTANT_ID = os.getenv("VAPI_ASSISTANT_ID", "")
ALERT_PHONE_NUMBER = os.getenv("ALERT_PHONE_NUMBER", "")
CALL_COOLDOWN_SECONDS = int(os.getenv("CALL_COOLDOWN_SECONDS", "300"))

VAPI_API_URL = "https://api.vapi.ai/call"


def is_configured() -> bool:
    """Check if VAPI is enabled and all required env vars are set."""
    return bool(
        VAPI_ENABLED
        and VAPI_API_KEY
        and VAPI_PHONE_NUMBER_ID
        and VAPI_ASSISTANT_ID
        and ALERT_PHONE_NUMBER
    )


def _check_cooldown(source_ip: str) -> bool:
    """Return True if this source_ip had a call within the cooldown window."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=CALL_COOLDOWN_SECONDS)
    with get_cursor(cursor_factory=dict_cursor()) as cur:
        cur.execute(
            "SELECT COUNT(*) as cnt FROM vapi_calls WHERE source_ip = %s AND created_at > %s",
            (source_ip, cutoff),
        )
        return cur.fetchone()["cnt"] > 0


def _extract_phi_list(event_data: dict) -> str:
    """Extract a comma-separated string of PHI types from event data."""
    phi_types = event_data.get("phi_types", [])
    if isinstance(phi_types, str):
        try:
            phi_types = json.loads(phi_types)
        except (json.JSONDecodeError, TypeError):
            phi_types = []
    return ", ".join(phi_types) if phi_types else "protected health information"


def _make_vapi_call(event_data: dict, broadcast_fn=None):
    """
    Synchronous function that calls VAPI API and records the result.
    Designed to run in a background thread.
    """
    event_id = event_data.get("event_id")
    source_ip = event_data.get("source_ip")
    phone = ALERT_PHONE_NUMBER

    # Insert a pending call record
    with get_cursor(cursor_factory=dict_cursor()) as cur:
        cur.execute(
            "INSERT INTO vapi_calls (event_id, source_ip, phone_number, status) "
            "VALUES (%s, %s, %s, 'initiated') RETURNING *",
            (event_id, source_ip, phone),
        )
        call_record = dict(cur.fetchone())

    call_db_id = call_record["id"]

    # Use the pre-configured VAPI assistant with variable overrides
    payload = {
        "phoneNumberId": VAPI_PHONE_NUMBER_ID,
        "assistantId": VAPI_ASSISTANT_ID,
        "assistantOverrides": {
            "variableValues": {
                "service": event_data.get("ai_service", "an AI service"),
                "phi_types": _extract_phi_list(event_data),
                "risk_score": str(event_data.get("risk_score", 0)),
                "action_taken": "redacted and forwarded",
                "timestamp": event_data.get("timestamp", ""),
                "department": "unknown",
            },
        },
        "customer": {"number": phone},
    }

    try:
        req = Request(
            VAPI_API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {VAPI_API_KEY}",
                "Content-Type": "application/json",
                "User-Agent": "ShadowGuard/1.0",
            },
            method="POST",
        )
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        with urlopen(req, timeout=10, context=ssl_ctx) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            vapi_call_id = body.get("id", "")

        with get_cursor() as cur:
            cur.execute(
                "UPDATE vapi_calls SET call_id = %s, status = 'queued' WHERE id = %s",
                (vapi_call_id, call_db_id),
            )

        logger.info("VAPI call initiated: %s for event %s", vapi_call_id, event_id)

        if broadcast_fn:
            broadcast_fn({
                "type": "voice_call",
                "data": {
                    "event_id": str(event_id),
                    "call_id": vapi_call_id,
                    "status": "queued",
                    "phone_number": phone,
                },
            })

    except HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        error_msg = f"HTTP {e.code}: {body_text[:500]}"
        logger.error("VAPI call failed for event %s: %s", event_id, error_msg)
    except URLError as e:
        error_msg = str(e)[:500]
        logger.error("VAPI call failed for event %s: %s", event_id, error_msg)
        with get_cursor() as cur:
            cur.execute(
                "UPDATE vapi_calls SET status = 'failed', error_message = %s WHERE id = %s",
                (error_msg, call_db_id),
            )


def maybe_trigger_call(event_data: dict, broadcast_fn=None):
    """
    Check if the event warrants a VAPI call and trigger it in a background thread.
    Called from create_event in main.py.
    """
    if not is_configured():
        return

    severity = event_data.get("severity", "")
    risk_score = event_data.get("risk_score", 0) or 0

    if severity not in ("critical", "high") or risk_score < 70:
        return

    source_ip = event_data.get("source_ip", "")
    if _check_cooldown(source_ip):
        logger.info("Skipping VAPI call for %s: cooldown active", source_ip)
        return

    thread = threading.Thread(
        target=_make_vapi_call,
        args=(event_data, broadcast_fn),
        daemon=True,
    )
    thread.start()
