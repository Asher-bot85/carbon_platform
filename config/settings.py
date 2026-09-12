"""
config/settings.py

Global configuration for EcoCapture OS.
Defines shared filesystem paths, mock secret material, network defaults,
and platform-wide operational thresholds. This module is intentionally
free of business logic - it is a single source of truth for constants
consumed by every other package (security, iot, ot_security, devsecops,
esg, blockchain, attack_sim, and the Streamlit app itself).
"""

import os
import secrets

# ---------------------------------------------------------------------------
# Filesystem / Logging Paths
# ---------------------------------------------------------------------------
# In the containerized deployment this directory is backed by a shared
# PersistentVolumeClaim (see carbon-platform-k8s.yaml) so that the
# attack_sim process and the Streamlit dashboard process both read/write
# the exact same audit trail file even when running as separate pods.
DEFAULT_LOG_DIR = os.environ.get("ECOCAPTURE_LOG_DIR", "/app/logs")

# Ensure the log directory exists safely with a fallback for restricted environments
try:
    os.makedirs(DEFAULT_LOG_DIR, exist_ok=True)
    LOG_DIR = DEFAULT_LOG_DIR
except (PermissionError, OSError):
    LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
    os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE_PATH = os.path.join(LOG_DIR, "audit_trail.log")

# ---------------------------------------------------------------------------
# Secret Material (Mock / Demo)
# ---------------------------------------------------------------------------
# In production this MUST be sourced from a KMS / Vault / K8s Secret and
# never generated at runtime. For this self-contained demo platform we
# fall back to a per-process ephemeral key if no environment variable is
# supplied, purely so cryptographic signing functions remain operational
# out of the box.
SECRET_KEY = os.environ.get("ECOCAPTURE_SECRET_KEY", secrets.token_hex(32))

# ---------------------------------------------------------------------------
# Network / Platform Defaults
# ---------------------------------------------------------------------------
DEFAULT_NETWORK_CONFIG = {
    "allowed_ingress_cidrs": ["10.0.0.0/8", "192.168.0.0/16"],
    "dashboard_port": 8501,
    "api_rate_limit_per_minute": 120,
    "tls_min_version": "TLSv1.2",
}

# ---------------------------------------------------------------------------
# Operational Thresholds
# ---------------------------------------------------------------------------
CO2_SAFE_LOWER_PPM = float(os.environ.get("CO2_SAFE_LOWER_PPM", 100))
CO2_SAFE_UPPER_PPM = float(os.environ.get("CO2_SAFE_UPPER_PPM", 2000))
TEMPERATURE_SAFE_LOWER_C = -10.0
TEMPERATURE_SAFE_UPPER_C = 45.0

# Number of IoT sensor nodes simulated across the fleet
DEFAULT_SENSOR_FLEET_SIZE = 6

# Purdue Model enforcement mode used by ot_security.ot_monitor
PURDUE_ENFORCEMENT_MODE = os.environ.get("PURDUE_ENFORCEMENT", "strict")

# Platform metadata
PLATFORM_NAME = "EcoCapture OS"
PLATFORM_VERSION = "1.0.0"
ORG_NAME = "EcoCapture Climate Infrastructure"
