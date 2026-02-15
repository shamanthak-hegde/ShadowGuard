"""
Pydantic models for ShadowGuard API request/response validation.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class EventCreate(BaseModel):
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    ai_service: Optional[str] = None
    request_method: Optional[str] = None
    request_path: Optional[str] = None
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    severity: Optional[str] = None
    phi_detected: bool = False
    phi_count: int = 0
    phi_types: Optional[list] = None
    phi_findings: Optional[list | dict] = None
    original_text: Optional[str] = None
    redacted_text: Optional[str] = None
    action: Optional[str] = None
    engine: Optional[str] = None
    response_time_ms: Optional[int] = None


class EventResponse(BaseModel):
    id: int
    event_id: str
    timestamp: datetime
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    ai_service: Optional[str] = None
    request_method: Optional[str] = None
    request_path: Optional[str] = None
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    phi_detected: bool = False
    phi_count: int = 0
    phi_types: Optional[list] = None
    phi_findings: Optional[list | dict] = None
    original_text: Optional[str] = None
    redacted_text: Optional[str] = None
    action: Optional[str] = None
    status: str = "active"
    engine: Optional[str] = None
    response_time_ms: Optional[int] = None
    created_at: datetime


class StatusUpdate(BaseModel):
    status: str = Field(..., pattern=r"^(active|mitigated|resolved)$")


class VapiCallResponse(BaseModel):
    id: int
    call_id: Optional[str] = None
    event_id: str
    source_ip: Optional[str] = None
    phone_number: Optional[str] = None
    status: str = "initiated"
    created_at: datetime
    ended_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    error_message: Optional[str] = None


class StatsResponse(BaseModel):
    total_requests: int
    phi_detected: int
    requests_redacted: int
    requests_clean: int
    avg_risk_score: float
    by_service: dict
    by_severity: dict
    by_hour: list
    recent_phi_types: dict
    timeline: list
