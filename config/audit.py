"""
config/audit.py

Standard file-based audit logger for EcoCapture OS.

Provides a consistent, parseable log line format that is shared by every
subsystem (IDS, DevSecOps scanner, OT monitor, attack simulator, ESG
reporter) and consumed in near-real-time by the Streamlit dashboard's
"Security Audit Trail" panel.

Log line format:
    <ISO8601 TIMESTAMP> | <LEVEL> | <SOURCE> | <MESSAGE>

Levels (in ascending severity):
    INFO, WARNING, HIGH, CRITICAL
"""

import os
import threading
from datetime import datetime, timezone

from config import settings

_VALID_LEVELS = ("INFO", "WARNING", "HIGH", "CRITICAL")

# A process-local lock to keep concurrent writes from a single process
# from interleaving. Cross-process writes (dashboard vs attack_sim) are
# append-only and line-atomic on POSIX filesystems for small writes,
# which is sufficient for this platform's demo/audit purposes.
_write_lock = threading.Lock()


class AuditLogger:
    """
    File-backed audit logger. Every subsystem should instantiate this
    with its own `source` identifier (e.g. "IDS", "DevSecOpsScanner",
    "OTMonitor", "AttackSimulator", "ESGReporter") so that log lines are
    traceable back to their origin component.
    """

    def __init__(self, source: str, log_path: str = None):
        self.source = source
        self.log_path = log_path or settings.LOG_FILE_PATH
        # Ensure parent directory exists (handles custom log_path usage)
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        # Touch the file so it exists even before the first write
        if not os.path.exists(self.log_path):
            with open(self.log_path, "a", encoding="utf-8"):
                pass

    def _write(self, level: str, message: str):
        if level not in _VALID_LEVELS:
            level = "INFO"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        line = f"{timestamp} | {level:<8} | {self.source:<20} | {message}\n"
        with _write_lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
        return line

    def info(self, message: str):
        return self._write("INFO", message)

    def warning(self, message: str):
        return self._write("WARNING", message)

    def high(self, message: str):
        return self._write("HIGH", message)

    def critical(self, message: str):
        return self._write("CRITICAL", message)

    def log(self, level: str, message: str):
        return self._write(level.upper(), message)


def parse_log_line(line: str) -> dict:
    """
    Parses a single audit log line back into a structured dict:
        {
            "timestamp": "2026-07-13 10:00:00 UTC",
            "level": "CRITICAL",
            "source": "AttackSimulator",
            "message": "SQL Injection payload detected..."
        }
    Returns None if the line does not match the expected format.
    """
    try:
        parts = line.rstrip("\n").split(" | ", 3)
        if len(parts) != 4:
            return None
        timestamp, level, source, message = parts
        return {
            "timestamp": timestamp.strip(),
            "level": level.strip(),
            "source": source.strip(),
            "message": message.strip(),
        }
    except Exception:
        return None


def read_log_lines(log_path: str = None, max_lines: int = 300) -> list:
    """
    Reads up to `max_lines` most recent lines from the audit log file,
    returned oldest-first for chronological display. Safe to call even
    if the file does not yet exist (returns an empty list).
    """
    path = log_path or settings.LOG_FILE_PATH
    if not os.path.exists(path):
        return []
    with _write_lock:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    tail = lines[-max_lines:] if len(lines) > max_lines else lines
    parsed = []
    for line in tail:
        record = parse_log_line(line)
        if record:
            parsed.append(record)
    return parsed


def get_default_logger(source: str = "EcoCaptureOS") -> AuditLogger:
    """Convenience factory returning a logger bound to the default path."""
    return AuditLogger(source=source)
