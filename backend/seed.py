"""
Seed the database with realistic demo data for ShadowGuard hackathon demo.
Generates 50-100 events spanning the last 2 hours.
"""

import random
import json
import uuid
from datetime import datetime, timedelta, timezone

DEPARTMENTS = ["ER", "Radiology", "Cardiology", "Oncology", "Pharmacy", "Admin"]

SERVICES = [
    ("ChatGPT", 60),
    ("Claude", 30),
    ("Gemini", 10),
]

SEVERITY_WEIGHTS = {
    "critical": 20,
    "high": 15,
    "medium": 25,
    "low": 15,
    "clean": 25,
}

PHI_TYPES_POOL = [
    "PERSON", "US_SSN", "PHONE_NUMBER", "EMAIL_ADDRESS",
    "DATE_OF_BIRTH", "MEDICAL_RECORD_NUMBER", "LOCATION",
    "DIAGNOSIS_CODE", "MEDICATION",
]

REALISTIC_MESSAGES = [
    {
        "original": "Patient John Smith, DOB 03/15/1985, MRN#12345 was admitted to ER with chest pain. His SSN is 123-45-6789. Contact at john.smith@hospital.org or 555-123-4567.",
        "redacted": "Patient [REDACTED_PERSON], DOB [REDACTED_DOB], [REDACTED_MRN] was admitted to ER with chest pain. His SSN is [REDACTED_SSN]. Contact at [REDACTED_EMAIL] or [REDACTED_PHONE].",
        "phi_types": ["PERSON", "DATE_OF_BIRTH", "MEDICAL_RECORD_NUMBER", "US_SSN", "EMAIL_ADDRESS", "PHONE_NUMBER"],
        "findings": [
            {"entity_type": "PERSON", "text": "John Smith", "score": 0.95},
            {"entity_type": "DATE_OF_BIRTH", "text": "03/15/1985", "score": 0.90},
            {"entity_type": "MEDICAL_RECORD_NUMBER", "text": "MRN#12345", "score": 0.99},
            {"entity_type": "US_SSN", "text": "123-45-6789", "score": 0.99},
            {"entity_type": "EMAIL_ADDRESS", "text": "john.smith@hospital.org", "score": 0.99},
            {"entity_type": "PHONE_NUMBER", "text": "555-123-4567", "score": 0.99},
        ],
    },
    {
        "original": "Summarize the lab results for Maria Garcia, MRN#67890. Her blood glucose is 250 mg/dL, HbA1c 9.2%. She lives at 123 Oak Ave, Springfield. Phone: 555-987-6543.",
        "redacted": "Summarize the lab results for [REDACTED_PERSON], [REDACTED_MRN]. Her blood glucose is 250 mg/dL, HbA1c 9.2%. She lives at [REDACTED_LOCATION]. Phone: [REDACTED_PHONE].",
        "phi_types": ["PERSON", "MEDICAL_RECORD_NUMBER", "LOCATION", "PHONE_NUMBER"],
        "findings": [
            {"entity_type": "PERSON", "text": "Maria Garcia", "score": 0.92},
            {"entity_type": "MEDICAL_RECORD_NUMBER", "text": "MRN#67890", "score": 0.99},
            {"entity_type": "LOCATION", "text": "123 Oak Ave, Springfield", "score": 0.88},
            {"entity_type": "PHONE_NUMBER", "text": "555-987-6543", "score": 0.99},
        ],
    },
    {
        "original": "Draft a discharge summary for Robert Johnson, SSN 987-65-4321. Diagnosis: E11.9 Type 2 Diabetes. Prescribed Metformin 500mg BID. Follow up with Dr. Chen at Radiology dept.",
        "redacted": "Draft a discharge summary for [REDACTED_PERSON], SSN [REDACTED_SSN]. Diagnosis: E11.9 Type 2 Diabetes. Prescribed Metformin 500mg BID. Follow up with [REDACTED_PERSON] at Radiology dept.",
        "phi_types": ["PERSON", "US_SSN", "DIAGNOSIS_CODE"],
        "findings": [
            {"entity_type": "PERSON", "text": "Robert Johnson", "score": 0.93},
            {"entity_type": "US_SSN", "text": "987-65-4321", "score": 0.99},
            {"entity_type": "PERSON", "text": "Dr. Chen", "score": 0.85},
        ],
    },
    {
        "original": "Can you help me understand the MRI report for patient Sarah Williams? She had a brain MRI on 01/10/2025. Contact her at sarah.w@email.com. MRN#11223.",
        "redacted": "Can you help me understand the MRI report for patient [REDACTED_PERSON]? She had a brain MRI on [REDACTED_DATE]. Contact her at [REDACTED_EMAIL]. [REDACTED_MRN].",
        "phi_types": ["PERSON", "DATE_OF_BIRTH", "EMAIL_ADDRESS", "MEDICAL_RECORD_NUMBER"],
        "findings": [
            {"entity_type": "PERSON", "text": "Sarah Williams", "score": 0.94},
            {"entity_type": "DATE_OF_BIRTH", "text": "01/10/2025", "score": 0.80},
            {"entity_type": "EMAIL_ADDRESS", "text": "sarah.w@email.com", "score": 0.99},
            {"entity_type": "MEDICAL_RECORD_NUMBER", "text": "MRN#11223", "score": 0.99},
        ],
    },
    {
        "original": "Patient David Lee, DOB 11/22/1970, presented with hypertension. BP 180/110. Current medications: Lisinopril 20mg, Amlodipine 5mg. Phone: 555-456-7890. Address: 456 Elm Blvd.",
        "redacted": "Patient [REDACTED_PERSON], DOB [REDACTED_DOB], presented with hypertension. BP 180/110. Current medications: Lisinopril 20mg, Amlodipine 5mg. Phone: [REDACTED_PHONE]. Address: [REDACTED_LOCATION].",
        "phi_types": ["PERSON", "DATE_OF_BIRTH", "PHONE_NUMBER", "LOCATION", "MEDICATION"],
        "findings": [
            {"entity_type": "PERSON", "text": "David Lee", "score": 0.91},
            {"entity_type": "DATE_OF_BIRTH", "text": "11/22/1970", "score": 0.90},
            {"entity_type": "PHONE_NUMBER", "text": "555-456-7890", "score": 0.99},
            {"entity_type": "LOCATION", "text": "456 Elm Blvd", "score": 0.85},
        ],
    },
    {
        "original": "What are the treatment options for a 45-year-old male with stage 3 chronic kidney disease?",
        "redacted": None,
        "phi_types": [],
        "findings": [],
    },
    {
        "original": "Explain the difference between Type 1 and Type 2 diabetes in simple terms for a patient education handout.",
        "redacted": None,
        "phi_types": [],
        "findings": [],
    },
    {
        "original": "What are the recommended dosing guidelines for vancomycin in pediatric patients?",
        "redacted": None,
        "phi_types": [],
        "findings": [],
    },
    {
        "original": "Help me create a template for a SOAP note for an outpatient cardiology visit.",
        "redacted": None,
        "phi_types": [],
        "findings": [],
    },
    {
        "original": "What are the current AHA guidelines for managing acute myocardial infarction?",
        "redacted": None,
        "phi_types": [],
        "findings": [],
    },
    {
        "original": "Can you explain how to interpret an arterial blood gas result?",
        "redacted": None,
        "phi_types": [],
        "findings": [],
    },
    {
        "original": "Please review the chart for Emily Zhang, MRN#33456. She was seen on 02/05/2025 by Dr. Patel in Oncology. SSN: 456-78-9012. Prescribed Tamoxifen 20mg daily.",
        "redacted": "Please review the chart for [REDACTED_PERSON], [REDACTED_MRN]. She was seen on [REDACTED_DATE] by [REDACTED_PERSON] in Oncology. SSN: [REDACTED_SSN]. Prescribed Tamoxifen 20mg daily.",
        "phi_types": ["PERSON", "MEDICAL_RECORD_NUMBER", "DATE_OF_BIRTH", "US_SSN"],
        "findings": [
            {"entity_type": "PERSON", "text": "Emily Zhang", "score": 0.93},
            {"entity_type": "MEDICAL_RECORD_NUMBER", "text": "MRN#33456", "score": 0.99},
            {"entity_type": "DATE_OF_BIRTH", "text": "02/05/2025", "score": 0.80},
            {"entity_type": "PERSON", "text": "Dr. Patel", "score": 0.87},
            {"entity_type": "US_SSN", "text": "456-78-9012", "score": 0.99},
        ],
    },
    {
        "original": "Transfer notes for James Brown from ER to ICU. DOB: 06/30/1958. Diagnosis: Acute respiratory failure. Contact: 555-321-0987, james.brown@mail.com.",
        "redacted": "Transfer notes for [REDACTED_PERSON] from ER to ICU. DOB: [REDACTED_DOB]. Diagnosis: Acute respiratory failure. Contact: [REDACTED_PHONE], [REDACTED_EMAIL].",
        "phi_types": ["PERSON", "DATE_OF_BIRTH", "PHONE_NUMBER", "EMAIL_ADDRESS"],
        "findings": [
            {"entity_type": "PERSON", "text": "James Brown", "score": 0.94},
            {"entity_type": "DATE_OF_BIRTH", "text": "06/30/1958", "score": 0.90},
            {"entity_type": "PHONE_NUMBER", "text": "555-321-0987", "score": 0.99},
            {"entity_type": "EMAIL_ADDRESS", "text": "james.brown@mail.com", "score": 0.99},
        ],
    },
]

REQUEST_PATHS = [
    "/v1/chat/completions",
    "/api/messages",
    "/v1/messages",
    "/backend-api/conversation",
    "/v1beta/models/gemini-pro:generateContent",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
    "Epic/2024.1 EHR-Integration/3.2",
    "Cerner-PowerChart/2024.2",
]


def _pick_service() -> str:
    r = random.randint(1, 100)
    if r <= 60:
        return "ChatGPT"
    elif r <= 90:
        return "Claude"
    else:
        return "Gemini"


def _pick_severity() -> str:
    r = random.randint(1, 100)
    if r <= 20:
        return "critical"
    elif r <= 35:
        return "high"
    elif r <= 60:
        return "medium"
    elif r <= 75:
        return "low"
    else:
        return "clean"


def _risk_for_severity(severity: str) -> int:
    ranges = {
        "critical": (71, 100),
        "high": (51, 70),
        "medium": (31, 50),
        "low": (11, 30),
        "clean": (0, 10),
    }
    lo, hi = ranges[severity]
    return random.randint(lo, hi)


def generate_seed_events(count: int = 75) -> list[dict]:
    """Generate realistic demo events."""
    now = datetime.now(timezone.utc)
    events = []

    for i in range(count):
        severity = _pick_severity()
        risk_score = _risk_for_severity(severity)
        service = _pick_service()
        has_phi = severity in ("critical", "high")

        # Pick a message template
        if has_phi:
            msg = random.choice([m for m in REALISTIC_MESSAGES if m["phi_types"]])
        else:
            msg = random.choice([m for m in REALISTIC_MESSAGES if not m["phi_types"]])

        # Spread events across last 2 hours
        offset_seconds = random.randint(0, 7200)
        ts = now - timedelta(seconds=offset_seconds)

        # Simulate hospital subnet IPs
        dept_octet = random.choice([10, 20, 30, 40, 50, 60])
        host_octet = random.randint(1, 254)
        source_ip = f"10.0.{dept_octet}.{host_octet}"

        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": ts.isoformat(),
            "source_ip": source_ip,
            "user_agent": random.choice(USER_AGENTS),
            "ai_service": service,
            "request_method": "POST",
            "request_path": random.choice(REQUEST_PATHS),
            "risk_score": risk_score,
            "severity": severity,
            "phi_detected": has_phi,
            "phi_count": len(msg["findings"]) if has_phi else 0,
            "phi_types": json.dumps(msg["phi_types"]) if msg["phi_types"] else json.dumps([]),
            "phi_findings": json.dumps(msg["findings"]) if msg["findings"] else json.dumps([]),
            "original_text": msg["original"],
            "redacted_text": msg["redacted"],
            "action": "redacted" if has_phi else "clean",
            "status": random.choice(["active", "active", "active", "mitigated", "resolved"]) if has_phi else "active",
            "engine": "presidio" if has_phi else "regex_fallback",
            "response_time_ms": random.randint(50, 500),
        }
        events.append(event)

    # Sort by timestamp
    events.sort(key=lambda e: e["timestamp"])
    return events


def insert_seed_events(cursor, events: list[dict]):
    """Insert seed events into the database."""
    for e in events:
        cursor.execute(
            """
            INSERT INTO events (
                event_id, timestamp, source_ip, user_agent, ai_service,
                request_method, request_path, risk_score, severity,
                phi_detected, phi_count, phi_types, phi_findings,
                original_text, redacted_text, action, status, engine,
                response_time_ms, created_at
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s
            )
            """,
            (
                e["event_id"], e["timestamp"], e["source_ip"], e["user_agent"],
                e["ai_service"], e["request_method"], e["request_path"],
                e["risk_score"], e["severity"], e["phi_detected"], e["phi_count"],
                e["phi_types"], e["phi_findings"], e["original_text"],
                e["redacted_text"], e["action"], e["status"], e["engine"],
                e["response_time_ms"], e["timestamp"],
            ),
        )
