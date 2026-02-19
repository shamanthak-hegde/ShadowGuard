"""
ShadowGuard FastAPI Backend
Healthcare Shadow AI Detection & Governance System

Run: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from database import init_db, get_cursor, dict_cursor, close_pool
from models import EventCreate, EventResponse, StatusUpdate, StatsResponse
from seed import generate_seed_events, insert_seed_events
from vapi_caller import maybe_trigger_call, is_configured as vapi_is_configured, _make_vapi_call, ALERT_PHONE_NUMBER


# ============================================================
# WebSocket Manager
# ============================================================

class ConnectionManager:
    """Manages active WebSocket connections for real-time broadcasts."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead = []
        for conn in self.active_connections:
            try:
                await conn.send_json(message)
            except Exception:
                dead.append(conn)
        for conn in dead:
            self.disconnect(conn)


manager = ConnectionManager()


def broadcast_from_thread(message: dict):
    """Schedule an async broadcast from a synchronous background thread."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(manager.broadcast(message), loop)
    except RuntimeError:
        pass


# ============================================================
# App Lifecycle
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    print("✅ Database initialized")
    yield
    # Shutdown
    close_pool()
    print("🛑 Database pool closed")


app = FastAPI(
    title="ShadowGuard API",
    description="Healthcare Shadow AI Detection & Governance",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow all origins for hackathon
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Helper
# ============================================================

def _row_to_dict(row: dict) -> dict:
    """Convert a database row to a JSON-serializable dict."""
    d = dict(row)
    for key in ("timestamp", "created_at"):
        if key in d and d[key] is not None:
            d[key] = d[key].isoformat()
    if "event_id" in d and d["event_id"] is not None:
        d["event_id"] = str(d["event_id"])
    # Parse JSONB fields that might be strings
    for key in ("phi_types", "phi_findings"):
        if key in d and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


# ============================================================
# Routes
# ============================================================

@app.get("/api/health")
def health_check():
    return {"status": "ok"}


def _sanitize(val):
    """Strip NUL bytes that PostgreSQL text fields reject."""
    if isinstance(val, str):
        return val.replace("\x00", "")
    return val


@app.post("/api/events", status_code=201)
async def create_event(event: EventCreate):
    """Ingest a new event from mitmproxy."""
    phi_types_json = json.dumps(event.phi_types) if event.phi_types else json.dumps([])
    phi_findings_json = json.dumps(event.phi_findings) if event.phi_findings else json.dumps([])

    with get_cursor(cursor_factory=dict_cursor()) as cur:
        cur.execute(
            """
            INSERT INTO events (
                source_ip, user_agent, ai_service, request_method, request_path,
                risk_score, severity, phi_detected, phi_count,
                phi_types, phi_findings, original_text, redacted_text,
                action, engine, response_time_ms
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s
            )
            RETURNING *
            """,
            (
                _sanitize(event.source_ip), _sanitize(event.user_agent), _sanitize(event.ai_service),
                _sanitize(event.request_method), _sanitize(event.request_path),
                event.risk_score, _sanitize(event.severity), event.phi_detected, event.phi_count,
                _sanitize(phi_types_json), _sanitize(phi_findings_json),
                _sanitize(event.original_text), _sanitize(event.redacted_text),
                _sanitize(event.action), _sanitize(event.engine), event.response_time_ms,
            ),
        )
        row = cur.fetchone()

    created = _row_to_dict(row)

    # Broadcast to WebSocket clients
    await manager.broadcast({"type": "new_event", "data": created})

    # Trigger VAPI voice call for high-risk events (non-blocking)
    maybe_trigger_call(created, broadcast_fn=broadcast_from_thread)

    return created


@app.get("/api/events")
def list_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = Query(None),
    service: str | None = Query(None),
    status: str | None = Query(None),
):
    """List events with pagination and optional filters."""
    query = "SELECT * FROM events WHERE 1=1"
    params: list = []

    if severity:
        query += " AND severity = %s"
        params.append(severity)
    if service:
        query += " AND ai_service = %s"
        params.append(service)
    if status:
        query += " AND status = %s"
        params.append(status)

    query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])

    with get_cursor(cursor_factory=dict_cursor()) as cur:
        cur.execute(query, params)
        rows = cur.fetchall()

    return [_row_to_dict(r) for r in rows]


@app.get("/api/events/{event_id}")
def get_event(event_id: str):
    """Get a single event by event_id (UUID)."""
    with get_cursor(cursor_factory=dict_cursor()) as cur:
        cur.execute("SELECT * FROM events WHERE event_id = %s", (event_id,))
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Event not found")

    return _row_to_dict(row)


@app.patch("/api/events/{event_id}/status")
async def update_event_status(event_id: str, body: StatusUpdate):
    """Update event status (active/mitigated/resolved)."""
    with get_cursor(cursor_factory=dict_cursor()) as cur:
        cur.execute(
            "UPDATE events SET status = %s WHERE event_id = %s RETURNING *",
            (body.status, event_id),
        )
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Event not found")

    updated = _row_to_dict(row)

    # Broadcast status change
    await manager.broadcast({
        "type": "status_update",
        "data": {"event_id": event_id, "status": body.status},
    })

    return updated


@app.get("/api/stats")
def get_stats():
    """Dashboard aggregate statistics."""
    with get_cursor(cursor_factory=dict_cursor()) as cur:
        # Total requests
        cur.execute("SELECT COUNT(*) as count FROM events")
        total_requests = cur.fetchone()["count"]

        # PHI detected count
        cur.execute("SELECT COUNT(*) as count FROM events WHERE phi_detected = TRUE")
        phi_detected = cur.fetchone()["count"]

        # Redacted count
        cur.execute("SELECT COUNT(*) as count FROM events WHERE action = 'redacted'")
        requests_redacted = cur.fetchone()["count"]

        # Clean count
        cur.execute("SELECT COUNT(*) as count FROM events WHERE action = 'clean'")
        requests_clean = cur.fetchone()["count"]

        # Average risk score
        cur.execute("SELECT COALESCE(AVG(risk_score), 0) as avg FROM events")
        avg_risk_score = round(float(cur.fetchone()["avg"]), 1)

        # By service
        cur.execute(
            "SELECT ai_service, COUNT(*) as count FROM events "
            "WHERE ai_service IS NOT NULL GROUP BY ai_service"
        )
        by_service = {r["ai_service"]: r["count"] for r in cur.fetchall()}

        # By severity
        cur.execute(
            "SELECT severity, COUNT(*) as count FROM events "
            "WHERE severity IS NOT NULL GROUP BY severity"
        )
        by_severity = {r["severity"]: r["count"] for r in cur.fetchall()}

        # By hour (last 24 hours)
        cur.execute("""
            SELECT
                date_trunc('hour', timestamp) as hour,
                COUNT(*) as count,
                SUM(CASE WHEN phi_detected THEN 1 ELSE 0 END) as phi_count
            FROM events
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY hour
            ORDER BY hour
        """)
        by_hour = []
        for r in cur.fetchall():
            by_hour.append({
                "hour": r["hour"].strftime("%H:%M") if r["hour"] else "",
                "count": r["count"],
                "phi_count": r["phi_count"],
            })

        # Recent PHI types (aggregate from JSONB)
        cur.execute("""
            SELECT elem as phi_type, COUNT(*) as count
            FROM events, jsonb_array_elements_text(phi_types) as elem
            WHERE phi_detected = TRUE
            GROUP BY elem
            ORDER BY count DESC
        """)
        recent_phi_types = {r["phi_type"]: r["count"] for r in cur.fetchall()}

        # Timeline (recent events for charting)
        cur.execute("""
            SELECT timestamp, risk_score, ai_service
            FROM events
            ORDER BY timestamp DESC
            LIMIT 200
        """)
        timeline = []
        for r in cur.fetchall():
            timeline.append({
                "timestamp": r["timestamp"].isoformat() if r["timestamp"] else "",
                "risk_score": r["risk_score"],
                "service": r["ai_service"],
            })

    return {
        "total_requests": total_requests,
        "phi_detected": phi_detected,
        "requests_redacted": requests_redacted,
        "requests_clean": requests_clean,
        "avg_risk_score": avg_risk_score,
        "by_service": by_service,
        "by_severity": by_severity,
        "by_hour": by_hour,
        "recent_phi_types": recent_phi_types,
        "timeline": timeline,
    }


@app.post("/api/seed")
def seed_database():
    """Seed the database with realistic demo data."""
    events = generate_seed_events(75)

    with get_cursor() as cur:
        # Clear existing data
        cur.execute("DELETE FROM vapi_calls")
        cur.execute("DELETE FROM events")
        insert_seed_events(cur, events)

    return {"message": f"Seeded {len(events)} events", "count": len(events)}


# ============================================================
# VAPI Voice Call Endpoints
# ============================================================

@app.get("/api/calls")
def list_calls(
    limit: int = Query(50, ge=1, le=200),
    event_id: str | None = Query(None),
):
    """List VAPI call records."""
    query = "SELECT * FROM vapi_calls WHERE 1=1"
    params: list = []

    if event_id:
        query += " AND event_id = %s"
        params.append(event_id)

    query += " ORDER BY created_at DESC LIMIT %s"
    params.append(limit)

    with get_cursor(cursor_factory=dict_cursor()) as cur:
        cur.execute(query, params)
        rows = cur.fetchall()

    result = []
    for row in rows:
        d = dict(row)
        for key in ("created_at", "ended_at"):
            if key in d and d[key] is not None:
                d[key] = d[key].isoformat()
        if "event_id" in d and d["event_id"] is not None:
            d["event_id"] = str(d["event_id"])
        result.append(d)
    return result


@app.get("/api/calls/stats")
def get_call_stats():
    """Aggregate voice call statistics."""
    with get_cursor(cursor_factory=dict_cursor()) as cur:
        cur.execute("SELECT COUNT(*) as total FROM vapi_calls")
        total = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) as cnt FROM vapi_calls WHERE status = 'failed'")
        failed = cur.fetchone()["cnt"]

        cur.execute(
            "SELECT COUNT(*) as cnt FROM vapi_calls WHERE status NOT IN ('failed', 'initiated')"
        )
        completed = cur.fetchone()["cnt"]

    return {
        "total_calls": total,
        "completed_calls": completed,
        "failed_calls": failed,
    }


@app.post("/api/calls/test")
def trigger_test_call():
    """Manually trigger a test VAPI call (for demo)."""
    if not vapi_is_configured():
        raise HTTPException(
            status_code=503,
            detail="VAPI not configured. Set VAPI_ENABLED=true, VAPI_API_KEY, VAPI_PHONE_NUMBER_ID, VAPI_ASSISTANT_ID, ALERT_PHONE_NUMBER.",
        )

    test_event = {
        "event_id": "00000000-0000-0000-0000-000000000000",
        "source_ip": "10.0.10.1",
        "ai_service": "ChatGPT",
        "risk_score": 95,
        "severity": "critical",
        "phi_types": ["PERSON", "US_SSN", "DATE_OF_BIRTH"],
    }
    # Insert call record synchronously, then fire the API call in a thread
    with get_cursor(cursor_factory=dict_cursor()) as cur:
        cur.execute(
            "INSERT INTO vapi_calls (event_id, source_ip, phone_number, status) "
            "VALUES (%s, %s, %s, 'initiated') RETURNING id",
            (test_event["event_id"], test_event["source_ip"], ALERT_PHONE_NUMBER),
        )
        call_db_id = cur.fetchone()["id"]

    import threading
    thread = threading.Thread(
        target=_make_vapi_call,
        args=(call_db_id, test_event, broadcast_from_thread),
        daemon=True,
    )
    thread.start()
    return {"message": "Test call triggered", "phone": ALERT_PHONE_NUMBER}


# ============================================================
# WebSocket
# ============================================================

@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, listen for client messages
            data = await websocket.receive_text()
            # Echo back as acknowledgment (clients don't need to send anything)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
