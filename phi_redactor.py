"""
ShadowGuard — PHI Detection & Redaction Engine
Uses Microsoft Presidio for production-grade PII/PHI detection,
with custom healthcare-specific recognizers layered on top.

Install:
    pip install presidio-analyzer presidio-anonymizer
    python -m spacy download en_core_web_lg

Usage:
    from phi_redactor import PHIRedactor

    redactor = PHIRedactor()
    result = redactor.analyze_and_redact("Patient John Doe, MRN 847291, SSN 423-91-8847")
    print(result["redacted_text"])
    print(result["findings"])
"""

import re
import json
import logging
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger("shadowguard.phi")

# ============================================================
# Try to import Presidio — fall back to regex if unavailable
# ============================================================

PRESIDIO_AVAILABLE = False

try:
    from presidio_analyzer import (
        AnalyzerEngine,
        PatternRecognizer,
        Pattern,
        RecognizerResult,
    )
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig

    PRESIDIO_AVAILABLE = True
    logger.info("Presidio loaded successfully")
except ImportError:
    logger.warning(
        "Presidio not installed — falling back to regex-based detection. "
        "Install with: pip install presidio-analyzer presidio-anonymizer && "
        "python -m spacy download en_core_web_lg"
    )


# ============================================================
# Custom Healthcare Recognizers (added on top of Presidio)
# ============================================================


def build_custom_recognizers():
    """Build healthcare-specific pattern recognizers for Presidio."""
    recognizers = []

    # Medical Record Number (MRN)
    mrn_recognizer = PatternRecognizer(
        supported_entity="MEDICAL_RECORD_NUMBER",
        name="MRN Recognizer",
        patterns=[
            Pattern(
                name="MRN_pattern_labeled",
                regex=r"\bMRN[\s:#]*(\d{5,12})\b",
                score=0.95,
            ),
            Pattern(
                name="MRN_pattern_standalone",
                regex=r"\b(?:medical\s*record\s*(?:number|no|#)?)\s*:?\s*(\d{5,12})\b",
                score=0.9,
            ),
        ],
        context=["mrn", "medical record", "record number", "chart"],
    )
    recognizers.append(mrn_recognizer)

    # ICD-10 Diagnosis Codes (e.g., E11.9, C50.9, I10)
    icd_recognizer = PatternRecognizer(
        supported_entity="DIAGNOSIS_CODE",
        name="ICD-10 Recognizer",
        patterns=[
            Pattern(
                name="ICD10_pattern",
                regex=r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b",
                score=0.6,
            ),
        ],
        context=[
            "diagnosis",
            "diagnosed",
            "icd",
            "code",
            "condition",
            "primary",
            "secondary",
            "assessment",
        ],
    )
    recognizers.append(icd_recognizer)

    # Date of Birth (explicit label)
    dob_recognizer = PatternRecognizer(
        supported_entity="DATE_OF_BIRTH",
        name="DOB Recognizer",
        patterns=[
            Pattern(
                name="DOB_labeled",
                regex=r"(?:DOB|date\s*of\s*birth)\s*:?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}",
                score=0.95,
            ),
        ],
    )
    recognizers.append(dob_recognizer)

    # Drug / Medication names (common ones)
    medication_recognizer = PatternRecognizer(
        supported_entity="MEDICATION",
        name="Medication Recognizer",
        patterns=[
            Pattern(
                name="common_meds",
                regex=(
                    r"\b(?:Metformin|Lisinopril|Atorvastatin|Amlodipine|"
                    r"Omeprazole|Metoprolol|Losartan|Gabapentin|"
                    r"Hydrochlorothiazide|Sertraline|Amoxicillin|"
                    r"Levothyroxine|Prednisone|Insulin|Warfarin|"
                    r"Ibuprofen|Acetaminophen|Aspirin)\b"
                ),
                score=0.4,
            ),
        ],
        context=[
            "prescribed",
            "medication",
            "drug",
            "dose",
            "mg",
            "daily",
            "bid",
            "tid",
        ],
    )
    recognizers.append(medication_recognizer)

    return recognizers


# ============================================================
# Regex-Only Fallback (when Presidio isn't installed)
# ============================================================

REGEX_PATTERNS = {
    "SSN": (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
    "MRN": (r"\bMRN[\s:#]*\d{5,}\b", "MRN [REDACTED_MRN]"),
    "DOB": (
        r"\b(?:DOB|date\s*of\s*birth)[\s:]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
        "DOB [REDACTED_DOB]",
    ),
    "PHONE": (r"\b\d{3}[-.)]\s*\d{3}[-.)]\s*\d{4}\b", "[REDACTED_PHONE]"),
    "EMAIL": (
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "[REDACTED_EMAIL]",
    ),
    "PATIENT_NAME": (
        r"\b(?:patient|pt)[\s:]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b",
        "patient [REDACTED_NAME]",
    ),
    "ADDRESS": (
        r"\b\d{1,5}\s+[A-Z][a-z]+\s+(?:St|Ave|Blvd|Dr|Rd|Ln|Way|Court|Circle|Place)\b",
        "[REDACTED_ADDRESS]",
    ),
}


def regex_redact(text: str) -> dict:
    """Fallback regex-based PHI redaction."""
    redacted = text
    findings = []

    for entity_type, (pattern, replacement) in REGEX_PATTERNS.items():
        matches = list(re.finditer(pattern, redacted, re.IGNORECASE))
        if matches:
            for m in matches:
                findings.append(
                    {
                        "entity_type": entity_type,
                        "text": m.group(),
                        "start": m.start(),
                        "end": m.end(),
                        "score": 0.85,
                    }
                )
            redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)

    return {
        "redacted_text": redacted,
        "findings": findings,
        "phi_detected": len(findings) > 0,
        "phi_count": len(findings),
        "entity_types_found": list(set(f["entity_type"] for f in findings)),
        "engine": "regex_fallback",
    }


# ============================================================
# Ollama LLM Engine (optional, requires local Ollama server)
# ============================================================

OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2:1b"

OLLAMA_SYSTEM_PROMPT = (
    "You are a HIPAA PHI detection system. Given text, identify ALL Protected Health Information entities.\n"
    'Return ONLY a JSON array of objects with "entity_type" and "text" fields. No explanation, no markdown.\n\n'
    "Entity types: PERSON, US_SSN, PHONE_NUMBER, EMAIL_ADDRESS, DATE_OF_BIRTH, "
    "MEDICAL_RECORD_NUMBER, DIAGNOSIS_CODE, MEDICATION, ADDRESS, DATE_TIME, LOCATION\n\n"
    'Example input: "Patient John Doe, SSN 423-91-8847, DOB 03/15/1958"\n'
    'Example output: [{"entity_type": "PERSON", "text": "John Doe"}, '
    '{"entity_type": "US_SSN", "text": "423-91-8847"}, '
    '{"entity_type": "DATE_OF_BIRTH", "text": "03/15/1958"}]\n\n'
    "If no PHI is found, return: []"
)

REDACTION_MAP = {
    "PERSON": "[REDACTED_NAME]",
    "US_SSN": "[REDACTED_SSN]",
    "PHONE_NUMBER": "[REDACTED_PHONE]",
    "EMAIL_ADDRESS": "[REDACTED_EMAIL]",
    "DATE_OF_BIRTH": "[REDACTED_DOB]",
    "MEDICAL_RECORD_NUMBER": "[REDACTED_MRN]",
    "DIAGNOSIS_CODE": "[REDACTED_DX]",
    "MEDICATION": "[REDACTED_MED]",
    "ADDRESS": "[REDACTED_ADDRESS]",
    "DATE_TIME": "[REDACTED_DATE]",
    "LOCATION": "[REDACTED_LOCATION]",
}


def _check_ollama() -> bool:
    """Check if Ollama is running and reachable."""
    try:
        req = Request(f"{OLLAMA_URL}/api/tags")
        with urlopen(req, timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


def ollama_redact(text: str) -> dict:
    """Use Ollama LLM to detect and redact PHI from text."""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": text,
        "system": OLLAMA_SYSTEM_PROMPT,
        "stream": False,
    }

    try:
        req = Request(
            f"{OLLAMA_URL}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            raw_response = body.get("response", "").strip()
    except (URLError, OSError, json.JSONDecodeError) as e:
        logger.warning("Ollama request failed: %s", e)
        return {
            "redacted_text": text,
            "findings": [],
            "phi_detected": False,
            "phi_count": 0,
            "entity_types_found": [],
            "engine": "ollama",
        }

    # Strip markdown fencing if the LLM wrapped the JSON
    cleaned = raw_response
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        # Remove first line (```json) and last line (```)
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines)

    try:
        entities = json.loads(cleaned)
        if not isinstance(entities, list):
            entities = []
    except (json.JSONDecodeError, TypeError):
        logger.warning("Ollama returned invalid JSON: %s", raw_response[:200])
        return {
            "redacted_text": text,
            "findings": [],
            "phi_detected": False,
            "phi_count": 0,
            "entity_types_found": [],
            "engine": "ollama",
        }

    # Build findings with start/end offsets and redact
    findings = []
    redacted = text

    # Sort by text length descending to avoid partial-match issues during replacement
    valid_entities = []
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        ent_text = ent.get("text", "")
        ent_type = ent.get("entity_type", "UNKNOWN")
        if ent_text and ent_text in text:
            valid_entities.append((ent_type, ent_text))

    valid_entities.sort(key=lambda x: len(x[1]), reverse=True)

    for ent_type, ent_text in valid_entities:
        start = text.find(ent_text)
        if start == -1:
            continue
        findings.append(
            {
                "entity_type": ent_type,
                "text": ent_text,
                "start": start,
                "end": start + len(ent_text),
                "score": 0.90,
            }
        )
        replacement = REDACTION_MAP.get(ent_type, "[REDACTED]")
        redacted = redacted.replace(ent_text, replacement)

    return {
        "redacted_text": redacted,
        "findings": findings,
        "phi_detected": len(findings) > 0,
        "phi_count": len(findings),
        "entity_types_found": list(set(f["entity_type"] for f in findings)),
        "engine": "ollama",
    }


# ============================================================
# Main PHI Redactor Class
# ============================================================


class PHIRedactor:
    """
    Production-grade PHI detection and redaction.
    Uses Presidio when available, falls back to regex.
    """

    def __init__(self, use_presidio: bool = True, use_ollama: bool = False):
        self.use_ollama = use_ollama
        if self.use_ollama:
            if _check_ollama():
                logger.info("Using Ollama (%s) PHI detection", OLLAMA_MODEL)
            else:
                logger.warning(
                    "Ollama not reachable at %s — falling back to regex", OLLAMA_URL
                )
                self.use_ollama = False

        self.use_presidio = use_presidio and PRESIDIO_AVAILABLE and not self.use_ollama

        if self.use_presidio:
            self._init_presidio()
        elif not self.use_ollama:
            logger.info("Using regex-based PHI detection")

    def _init_presidio(self):
        """Initialize Presidio analyzer and anonymizer engines."""
        # Create analyzer with default NLP engine (spaCy)
        self.analyzer = AnalyzerEngine()

        # Register custom healthcare recognizers
        for recognizer in build_custom_recognizers():
            self.analyzer.registry.add_recognizer(recognizer)

        # Create anonymizer
        self.anonymizer = AnonymizerEngine()

        # Define how each entity type should be anonymized
        self.operators = {
            "PERSON": OperatorConfig("replace", {"new_value": "[REDACTED_NAME]"}),
            "PHONE_NUMBER": OperatorConfig(
                "replace", {"new_value": "[REDACTED_PHONE]"}
            ),
            "EMAIL_ADDRESS": OperatorConfig(
                "replace", {"new_value": "[REDACTED_EMAIL]"}
            ),
            "US_SSN": OperatorConfig("replace", {"new_value": "[REDACTED_SSN]"}),
            "LOCATION": OperatorConfig("replace", {"new_value": "[REDACTED_LOCATION]"}),
            "DATE_TIME": OperatorConfig("replace", {"new_value": "[REDACTED_DATE]"}),
            "MEDICAL_RECORD_NUMBER": OperatorConfig(
                "replace", {"new_value": "[REDACTED_MRN]"}
            ),
            "DIAGNOSIS_CODE": OperatorConfig("replace", {"new_value": "[REDACTED_DX]"}),
            "DATE_OF_BIRTH": OperatorConfig("replace", {"new_value": "[REDACTED_DOB]"}),
            "MEDICATION": OperatorConfig("replace", {"new_value": "[REDACTED_MED]"}),
            "US_DRIVER_LICENSE": OperatorConfig(
                "replace", {"new_value": "[REDACTED_LICENSE]"}
            ),
            "CREDIT_CARD": OperatorConfig("replace", {"new_value": "[REDACTED_CC]"}),
            "IP_ADDRESS": OperatorConfig("replace", {"new_value": "[REDACTED_IP]"}),
            # Default for anything else Presidio catches
            "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
        }

        # Entities to scan for
        self.entities = [
            "PERSON",
            "PHONE_NUMBER",
            "EMAIL_ADDRESS",
            "US_SSN",
            "LOCATION",
            "DATE_TIME",
            "MEDICAL_RECORD_NUMBER",
            "DIAGNOSIS_CODE",
            "DATE_OF_BIRTH",
            "MEDICATION",
            "US_DRIVER_LICENSE",
            "CREDIT_CARD",
            "IP_ADDRESS",
        ]

        logger.info(
            f"Presidio initialized with {len(self.entities)} entity types "
            f"+ {len(build_custom_recognizers())} custom healthcare recognizers"
        )

    def analyze_and_redact(
        self,
        text: str,
        score_threshold: float = 0.4,
    ) -> dict:
        """
        Detect and redact PHI from text.

        Returns:
            {
                "redacted_text": "Patient [REDACTED_NAME], MRN [REDACTED_MRN]...",
                "findings": [{"entity_type": "PERSON", "text": "John Doe", ...}, ...],
                "phi_detected": True,
                "phi_count": 5,
                "entity_types_found": ["PERSON", "US_SSN", "MEDICAL_RECORD_NUMBER"],
                "engine": "presidio" | "regex_fallback",
            }
        """
        if not text or not text.strip():
            return {
                "redacted_text": text,
                "findings": [],
                "phi_detected": False,
                "phi_count": 0,
                "entity_types_found": [],
                "engine": "none",
            }

        if self.use_ollama:
            return ollama_redact(text)

        if not self.use_presidio:
            return regex_redact(text)

        # Run Presidio analysis
        try:
            analyzer_results = self.analyzer.analyze(
                text=text,
                language="en",
                entities=self.entities,
                score_threshold=score_threshold,
            )
        except Exception as e:
            logger.error(f"Presidio analysis failed: {e}, falling back to regex")
            return regex_redact(text)

        # Build findings list (before anonymization, so we have original text)
        findings = []
        for result in analyzer_results:
            findings.append(
                {
                    "entity_type": result.entity_type,
                    "text": text[result.start : result.end],
                    "start": result.start,
                    "end": result.end,
                    "score": round(result.score, 2),
                }
            )

        # Run Presidio anonymization
        try:
            anonymized = self.anonymizer.anonymize(
                text=text,
                analyzer_results=analyzer_results,
                operators=self.operators,
            )
            redacted_text = anonymized.text
        except Exception as e:
            logger.error(f"Presidio anonymization failed: {e}, falling back to regex")
            return regex_redact(text)

        return {
            "redacted_text": redacted_text,
            "findings": findings,
            "phi_detected": len(findings) > 0,
            "phi_count": len(findings),
            "entity_types_found": list(set(f["entity_type"] for f in findings)),
            "engine": "presidio",
        }

    def analyze_only(self, text: str, score_threshold: float = 0.4) -> dict:
        """Detect PHI without redacting (for risk scoring only)."""
        if not text or not text.strip():
            return {"findings": [], "phi_detected": False, "phi_count": 0}

        if self.use_ollama:
            result = ollama_redact(text)
            return {
                "findings": result["findings"],
                "phi_detected": result["phi_detected"],
                "phi_count": result["phi_count"],
            }

        if not self.use_presidio:
            result = regex_redact(text)
            return {
                "findings": result["findings"],
                "phi_detected": result["phi_detected"],
                "phi_count": result["phi_count"],
            }

        try:
            results = self.analyzer.analyze(
                text=text,
                language="en",
                entities=self.entities,
                score_threshold=score_threshold,
            )
            findings = [
                {
                    "entity_type": r.entity_type,
                    "text": text[r.start : r.end],
                    "start": r.start,
                    "end": r.end,
                    "score": round(r.score, 2),
                }
                for r in results
            ]
            return {
                "findings": findings,
                "phi_detected": len(findings) > 0,
                "phi_count": len(findings),
            }
        except Exception as e:
            logger.error(f"Presidio analysis failed: {e}")
            result = regex_redact(text)
            return {
                "findings": result["findings"],
                "phi_detected": result["phi_detected"],
                "phi_count": result["phi_count"],
            }


# ============================================================
# Quick self-test
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  ShadowGuard PHI Redactor — Self Test")
    print("=" * 60)
    print(f"Engine: {'Presidio' if PRESIDIO_AVAILABLE else 'Regex Fallback'}")
    print()

    redactor = PHIRedactor()

    test_cases = [
        # Low risk — no PHI
        "How do I implement quicksort in Python?",
        # Medium risk — medical but no identifiers
        "What's the treatment protocol for Type 2 Diabetes with A1C above 9?",
        # High risk — full PHI
        (
            "Summarize discharge notes: Patient John Michael Doe, "
            "MRN: 847291034, DOB: 03/15/1958, SSN: 423-91-8847, "
            "Phone: 555-867-5309, Email: johndoe@email.com, "
            "Address: 1423 Oak Drive Springfield. "
            "Diagnosis: E11.9 Type 2 Diabetes. "
            "Prescribed Metformin 1000mg BID, Lisinopril 20mg daily. "
            "Blood pressure 128/82. A1C improved from 9.2 to 8.1."
        ),
        # Another PHI case
        (
            "Write a referral for patient Jane Smith, MRN: 993847, "
            "DOB: 11/22/1985, SSN: 291-55-8834. "
            "Diagnosed with C50.9 breast cancer."
        ),
    ]

    for i, text in enumerate(test_cases):
        print(f"{'─' * 60}")
        print(f"Test {i + 1}:")
        print(f"  Input:    {text[:80]}{'...' if len(text) > 80 else ''}")

        result = redactor.analyze_and_redact(text)

        print(f"  PHI:      {'🚨 YES' if result['phi_detected'] else '✅ None'}")
        print(f"  Count:    {result['phi_count']}")
        print(f"  Types:    {result['entity_types_found']}")
        print(f"  Engine:   {result['engine']}")
        print(
            f"  Redacted: {result['redacted_text'][:80]}{'...' if len(result['redacted_text']) > 80 else ''}"
        )

        if result["findings"]:
            print(f"  Findings:")
            for f in result["findings"]:
                print(
                    f'    • {f["entity_type"]}: "{f["text"]}" (confidence: {f["score"]})'
                )
        print()

    print("=" * 60)
    print("✅ Self-test complete!")
