"""
EcoCapture OS - DevSecOps Package
Implements static analysis scanning of Kubernetes manifests for
privilege escalation and container hardening risks.
"""

from . import pipeline

__all__ = ["pipeline"]
