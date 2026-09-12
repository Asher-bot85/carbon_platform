"""
devsecops/pipeline.py

Static security scanner for user-supplied Kubernetes manifest YAML.
Detects common privilege-escalation and container-hardening anti-patterns
such as running privileged containers, running as root (UID 0), enabling
allowPrivilegeEscalation, using the host network/PID/IPC namespaces, and
adding dangerous Linux capabilities.

Designed to be resilient to malformed or partial YAML: it performs both
a structural (parsed) scan and a raw-text regex scan so that findings are
still surfaced even if the pasted manifest is not fully valid YAML.
"""

import re

import yaml

from config.audit import AuditLogger

_logger = AuditLogger(source="DevSecOpsScanner")

_SEVERITY_CRITICAL = "CRITICAL"
_SEVERITY_HIGH = "HIGH"
_SEVERITY_MEDIUM = "MEDIUM"

_DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "DAC_READ_SEARCH", "SYS_RAWIO", "ALL",
}

_RAW_TEXT_RULES = [
    (r"privileged\s*:\s*true", "Privileged container mode enabled", _SEVERITY_CRITICAL),
    (r"runAsUser\s*:\s*0\b", "Container configured to run as root (UID 0)", _SEVERITY_CRITICAL),
    (r"allowPrivilegeEscalation\s*:\s*true", "allowPrivilegeEscalation is enabled", _SEVERITY_HIGH),
    (r"hostNetwork\s*:\s*true", "Pod uses the host network namespace", _SEVERITY_HIGH),
    (r"hostPID\s*:\s*true", "Pod uses the host PID namespace", _SEVERITY_HIGH),
    (r"hostIPC\s*:\s*true", "Pod uses the host IPC namespace", _SEVERITY_HIGH),
    (r"readOnlyRootFilesystem\s*:\s*false", "Root filesystem is writable", _SEVERITY_MEDIUM),
    (r"automountServiceAccountToken\s*:\s*true", "Service account token auto-mounted", _SEVERITY_MEDIUM),
]


def _scan_raw_text(yaml_text: str) -> list:
    findings = []
    for pattern, description, severity in _RAW_TEXT_RULES:
        for match in re.finditer(pattern, yaml_text, re.IGNORECASE):
            line_number = yaml_text[: match.start()].count("\n") + 1
            findings.append(
                {
                    "rule": pattern,
                    "description": description,
                    "severity": severity,
                    "line": line_number,
                    "source": "raw_text_scan",
                }
            )

    # Dangerous capability additions, e.g.:
    # capabilities:
    #   add: ["SYS_ADMIN"]
    cap_block_matches = re.finditer(
        r"capabilities\s*:\s*\n(?:\s+.*\n?)*?\s*add\s*:\s*(\[[^\]]*\]|(?:\n\s*-\s*\w+)+)",
        yaml_text,
        re.IGNORECASE,
    )
    for match in cap_block_matches:
        block = match.group(0)
        for cap in _DANGEROUS_CAPABILITIES:
            if cap in block.upper():
                line_number = yaml_text[: match.start()].count("\n") + 1
                findings.append(
                    {
                        "rule": f"capabilities.add contains {cap}",
                        "description": f"Dangerous Linux capability '{cap}' added to container",
                        "severity": _SEVERITY_CRITICAL if cap in ("SYS_ADMIN", "ALL") else _SEVERITY_HIGH,
                        "line": line_number,
                        "source": "raw_text_scan",
                    }
                )
    return findings


def _walk_structure(obj, path="root"):
    """Recursively yields (path, key, value) tuples from parsed YAML."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield (path, key, value)
            yield from _walk_structure(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            yield from _walk_structure(item, f"{path}[{idx}]")


def _scan_parsed_documents(documents: list) -> list:
    findings = []
    for doc_index, doc in enumerate(documents):
        if not isinstance(doc, (dict, list)):
            continue
        kind = doc.get("kind", "Unknown") if isinstance(doc, dict) else "Unknown"
        for path, key, value in _walk_structure(doc, f"doc[{doc_index}]({kind})"):
            if key == "privileged" and value is True:
                findings.append(
                    {
                        "rule": "securityContext.privileged == true",
                        "description": f"Privileged container detected at {path}",
                        "severity": _SEVERITY_CRITICAL,
                        "line": None,
                        "source": "structural_scan",
                    }
                )
            if key == "runAsUser" and value == 0:
                findings.append(
                    {
                        "rule": "securityContext.runAsUser == 0",
                        "description": f"Container running as root (UID 0) at {path}",
                        "severity": _SEVERITY_CRITICAL,
                        "line": None,
                        "source": "structural_scan",
                    }
                )
            if key == "allowPrivilegeEscalation" and value is True:
                findings.append(
                    {
                        "rule": "securityContext.allowPrivilegeEscalation == true",
                        "description": f"Privilege escalation allowed at {path}",
                        "severity": _SEVERITY_HIGH,
                        "line": None,
                        "source": "structural_scan",
                    }
                )
            if key in ("hostNetwork", "hostPID", "hostIPC") and value is True:
                findings.append(
                    {
                        "rule": f"{key} == true",
                        "description": f"Host namespace sharing ({key}) enabled at {path}",
                        "severity": _SEVERITY_HIGH,
                        "line": None,
                        "source": "structural_scan",
                    }
                )
            if key == "add" and isinstance(value, list):
                for cap in value:
                    if isinstance(cap, str) and cap.upper() in _DANGEROUS_CAPABILITIES:
                        findings.append(
                            {
                                "rule": f"capabilities.add contains {cap}",
                                "description": f"Dangerous capability '{cap}' added at {path}",
                                "severity": _SEVERITY_CRITICAL if cap.upper() in ("SYS_ADMIN", "ALL") else _SEVERITY_HIGH,
                                "line": None,
                                "source": "structural_scan",
                            }
                        )
    return findings


def scan_manifest(yaml_text: str) -> dict:
    """
    Scans a user-pasted Kubernetes manifest (one or more YAML documents)
    for privilege escalation and container hardening risks.

    Args:
        yaml_text: Raw YAML text as pasted by the user in the DevSecOps
                   Pipeline Manifest Scanner UI tab.

    Returns:
        dict: {
            "threat_count": int,
            "critical_count": int,
            "high_count": int,
            "medium_count": int,
            "findings": list[dict],
            "parse_error": str or None,
            "risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEAN"
        }
    """
    if not yaml_text or not yaml_text.strip():
        return {
            "threat_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "findings": [],
            "parse_error": None,
            "risk_level": "CLEAN",
        }

    parse_error = None
    parsed_documents = []
    try:
        parsed_documents = [doc for doc in yaml.safe_load_all(yaml_text) if doc is not None]
    except yaml.YAMLError as exc:
        parse_error = f"YAML parsing failed: {exc}. Falling back to raw-text pattern scan only."

    findings = []
    findings.extend(_scan_raw_text(yaml_text))
    if parsed_documents:
        findings.extend(_scan_parsed_documents(parsed_documents))

    # De-duplicate findings that were caught by both scan methods
    deduped = []
    seen = set()
    for finding in findings:
        fingerprint = (finding["rule"], finding["description"])
        if fingerprint not in seen:
            seen.add(fingerprint)
            deduped.append(finding)

    critical_count = sum(1 for f in deduped if f["severity"] == _SEVERITY_CRITICAL)
    high_count = sum(1 for f in deduped if f["severity"] == _SEVERITY_HIGH)
    medium_count = sum(1 for f in deduped if f["severity"] == _SEVERITY_MEDIUM)
    threat_count = len(deduped)

    if critical_count > 0:
        risk_level = "CRITICAL"
    elif high_count > 0:
        risk_level = "HIGH"
    elif medium_count > 0:
        risk_level = "MEDIUM"
    elif threat_count > 0:
        risk_level = "LOW"
    else:
        risk_level = "CLEAN"

    if threat_count > 0:
        _logger.log(
            "CRITICAL" if risk_level == "CRITICAL" else "HIGH" if risk_level == "HIGH" else "WARNING",
            f"Manifest scan completed: {threat_count} findings "
            f"(critical={critical_count}, high={high_count}, medium={medium_count}), "
            f"overall risk_level={risk_level}",
        )
    else:
        _logger.info("Manifest scan completed with no findings (CLEAN).")

    return {
        "threat_count": threat_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "findings": deduped,
        "parse_error": parse_error,
        "risk_level": risk_level,
    }
