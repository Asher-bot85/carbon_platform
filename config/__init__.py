"""
EcoCapture OS - Configuration Package
Exposes global settings and the audit logging subsystem used across
every module in the platform.
"""

from . import settings
from . import audit

__all__ = ["settings", "audit"]
