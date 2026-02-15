"""
PostgreSQL connection and table creation for ShadowGuard.
Uses psycopg2 with a connection pool.
"""

import os
import psycopg2
from psycopg2 import pool, extras
from contextlib import contextmanager

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://shadowguard:shadowguard@localhost:5432/shadowguard",
)

# Parse DATABASE_URL into components
def _parse_dsn(url: str) -> dict:
    # postgresql://user:pass@host:port/dbname
    url = url.replace("postgresql://", "")
    userpass, rest = url.split("@", 1)
    user, password = userpass.split(":", 1)
    hostport, dbname = rest.split("/", 1)
    if ":" in hostport:
        host, port = hostport.split(":", 1)
    else:
        host = hostport
        port = "5432"
    return {
        "user": user,
        "password": password,
        "host": host,
        "port": int(port),
        "dbname": dbname,
    }


_pool: pool.SimpleConnectionPool | None = None


def get_pool() -> pool.SimpleConnectionPool:
    global _pool
    if _pool is None:
        params = _parse_dsn(DATABASE_URL)
        _pool = pool.SimpleConnectionPool(minconn=2, maxconn=10, **params)
    return _pool


@contextmanager
def get_connection():
    """Get a connection from the pool, auto-return on exit."""
    p = get_pool()
    conn = p.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        p.putconn(conn)


@contextmanager
def get_cursor(cursor_factory=None):
    """Get a cursor with auto-commit/rollback."""
    with get_connection() as conn:
        kwargs = {}
        if cursor_factory:
            kwargs["cursor_factory"] = cursor_factory
        cur = conn.cursor(**kwargs)
        try:
            yield cur
        finally:
            cur.close()


def dict_cursor():
    """Return RealDictCursor factory for dict-like rows."""
    return extras.RealDictCursor


def init_db():
    """Create the events table if it doesn't exist."""
    with get_cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id              SERIAL PRIMARY KEY,
                event_id        UUID DEFAULT gen_random_uuid(),
                timestamp       TIMESTAMPTZ DEFAULT NOW(),
                source_ip       TEXT,
                user_agent      TEXT,
                ai_service      TEXT,
                request_method  TEXT,
                request_path    TEXT,
                risk_score      INTEGER,
                severity        TEXT,
                phi_detected    BOOLEAN DEFAULT FALSE,
                phi_count       INTEGER DEFAULT 0,
                phi_types       JSONB,
                phi_findings    JSONB,
                original_text   TEXT,
                redacted_text   TEXT,
                action          TEXT,
                status          TEXT DEFAULT 'active',
                engine          TEXT,
                response_time_ms INTEGER,
                created_at      TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        # Create index on event_id for fast lookups
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
        """)


def close_pool():
    """Close all connections in the pool."""
    global _pool
    if _pool:
        _pool.closeall()
        _pool = None
