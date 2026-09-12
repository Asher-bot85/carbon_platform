"""
security/ids.py

A lightweight, dependency-free Intrusion Detection System (IDS) for
EcoCapture OS. `inspect_traffic()` is the single entry point used by
every ingestion path in the platform (IoT telemetry ingestion, ESG data
submission, and the attack simulator) to validate untrusted input before
it is processed further.

Detection categories:
    1. SQL Injection signatures
    2. Directory / path traversal signatures
    3. Out-of-bounds / excessive CO2 injection commands
    4. Generic command-injection / shell metacharacter abuse

Any BLOCKED verdict is automatically written to the shared audit trail
as a CRITICAL event, which the Streamlit dashboard picks up in its
real-time Security Audit Trail view.
"""

import re

from config import settings
from config.audit import AuditLogger

_logger = AuditLogger(source="IDS")

# ---------------------------------------------------------------------------
# Signature Definitions
# ---------------------------------------------------------------------------
SQL_INJECTION_PATTERNS = [
    r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",  # OR 1=1
    r"union\s+select",
    r"drop\s+table",
    r"insert\s+into",
    r"delete\s+from",
    r"update\s+\w+\s+set",
    r"--\s*$",
    r";\s*--",
    r"xp_cmdshell",
    r"'\s*or\s*'\s*'\s*=\s*'",
    r"sleep\(\s*\d+\s*\)",
    r"benchmark\(",
]

DIRECTORY_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.\.%2f",
    r"/etc/passwd",
    r"/etc/shadow",
    r"c:\\windows\\system32",
]

COMMAND_INJECTION_PATTERNS = [
    r";\s*rm\s+-rf",
    r"\|\s*nc\s+",
    r"`.*`",
    r"\$\(.*\)",
    r"&&\s*cat\s+",
    r">\s*/dev/null",
    r"wget\s+http",
    r"curl\s+http",
]

# CO2 injection commands: patterns that look like an attacker attempting to
# force the carbon-capture control plane to report or command values far
# outside physically plausible / safe operating ranges (essentially a
# process-control integrity attack against the OT layer).
CO2_INJECTION_COMMAND_PATTERNS = [
    r"set_co2_override\s*=\s*-?\d+",
    r"force_valve\s*=\s*(open|closed)",
    r"disable_safety_interlock",
    r"co2_ppm\s*=\s*-?\d{5,}",
    r"override_purdue_zone",
    r"bypass_scrubber",
]


def _matches_any(patterns, text_lower):
    for pattern in patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return pattern
    return None


def _extract_numeric_co2(text: str):
    """Best-effort extraction of a co2_ppm-like numeric value from a string."""
    match = re.search(r"co2_ppm['\"]?\s*[:=]\s*(-?\d+(\.\d+)?)", text, re.IGNORECASE)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return None
    return None


def inspect_traffic(data: str, source: str = "unknown") -> dict:
    """
    Inspects an inbound payload (string) for known malicious signatures.

    Args:
        data: The raw payload string to inspect (e.g. a JSON body,
              a query string, a sensor telemetry submission, or a
              free-text field from a form).
        source: Logical origin of the traffic, used for audit context
                (e.g. "iot_ingest", "esg_upload", "attack_sim").

    Returns:
        dict: {
            "status": "BLOCKED" | "ALLOWED",
            "details": <human readable explanation>,
            "category": <threat category or None>,
            "matched_pattern": <regex that triggered, or None>
        }
    """
    if data is None:
        return {
            "status": "ALLOWED",
            "details": "Empty payload received; nothing to inspect.",
            "category": None,
            "matched_pattern": None,
        }

    text = str(data)
    text_lower = text.lower()

    # 1. SQL Injection
    matched = _matches_any(SQL_INJECTION_PATTERNS, text_lower)
    if matched:
        details = f"SQL Injection signature detected in payload from '{source}'."
        _logger.critical(
            f"BLOCKED payload from source='{source}' | category=SQL_INJECTION | "
            f"pattern='{matched}' | raw_snippet='{text[:120]}'"
        )
        return {
            "status": "BLOCKED",
            "details": details,
            "category": "SQL_INJECTION",
            "matched_pattern": matched,
        }

    # 2. Directory Traversal
    matched = _matches_any(DIRECTORY_TRAVERSAL_PATTERNS, text_lower)
    if matched:
        details = f"Directory traversal signature detected in payload from '{source}'."
        _logger.critical(
            f"BLOCKED payload from source='{source}' | category=DIRECTORY_TRAVERSAL | "
            f"pattern='{matched}' | raw_snippet='{text[:120]}'"
        )
        return {
            "status": "BLOCKED",
            "details": details,
            "category": "DIRECTORY_TRAVERSAL",
            "matched_pattern": matched,
        }

    # 3. Command Injection
    matched = _matches_any(COMMAND_INJECTION_PATTERNS, text_lower)
    if matched:
        details = f"Command injection signature detected in payload from '{source}'."
        _logger.critical(
            f"BLOCKED payload from source='{source}' | category=COMMAND_INJECTION | "
            f"pattern='{matched}' | raw_snippet='{text[:120]}'"
        )
        return {
            "status": "BLOCKED",
            "details": details,
            "category": "COMMAND_INJECTION",
            "matched_pattern": matched,
        }

    # 4. Excessive / malicious CO2 injection commands
    matched = _matches_any(CO2_INJECTION_COMMAND_PATTERNS, text_lower)
    if matched:
        details = (
            f"Malicious OT command / CO2 override injection detected from '{source}'. "
            "Possible attempt to manipulate carbon capture control plane."
        )
        _logger.critical(
            f"BLOCKED payload from source='{source}' | category=CO2_COMMAND_INJECTION | "
            f"pattern='{matched}' | raw_snippet='{text[:120]}'"
        )
        return {
            "status": "BLOCKED",
            "details": details,
            "category": "CO2_COMMAND_INJECTION",
            "matched_pattern": matched,
        }

    # 5. Out-of-bounds numeric CO2 value check (not a keyword match, a
    #    physical-plausibility / safety-envelope check on parsed values)
    co2_value = _extract_numeric_co2(text)
    if co2_value is not None:
        if co2_value < 0 or co2_value > settings.CO2_SAFE_UPPER_PPM * 5:
            details = (
                f"Out-of-bounds CO2 telemetry value ({co2_value} ppm) submitted from "
                f"'{source}'. Value exceeds physically plausible safety envelope."
            )
            _logger.critical(
                f"BLOCKED payload from source='{source}' | category=CO2_OUT_OF_BOUNDS | "
                f"value={co2_value} | raw_snippet='{text[:120]}'"
            )
            return {
                "status": "BLOCKED",
                "details": details,
                "category": "CO2_OUT_OF_BOUNDS",
                "matched_pattern": f"co2_ppm={co2_value}",
            }

    # Nothing matched -> allow, but still log at INFO for traceability
    _logger.info(f"ALLOWED payload from source='{source}' | raw_snippet='{text[:80]}'")
    return {
        "status": "ALLOWED",
        "details": "No known malicious signatures detected.",
        "category": None,
        "matched_pattern": None,
    }
