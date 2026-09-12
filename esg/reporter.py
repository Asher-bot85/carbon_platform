"""
esg/reporter.py

Compiles ESG (Environmental, Social, Governance) climate footprint
statements from simulated IoT fleet telemetry, and signs the resulting
report with mock cryptographic tracking metadata using the blockchain
ledger and platform secret key. This produces a tamper-evident audit
record suitable for downstream compliance/regulatory review.
"""

import hashlib
import json
from datetime import datetime, timezone

from config import settings
from config.audit import AuditLogger
from blockchain.ledger import sign_payload

_logger = AuditLogger(source="ESGReporter")

# Emission-factor style constants used purely for illustrative footprint
# math in this simulated reporting context.
_GRID_CARBON_INTENSITY_KG_PER_KWH = 0.42
_FACILITY_ENERGY_KWH_PER_TON_CAPTURED = 1800


def _compute_signature(report_body: dict) -> str:
    """
    Produces a mock cryptographic signature (HMAC-style SHA-256 digest)
    over the canonicalized report body using the platform secret key.
    This is a demonstration of tamper-evident signing, not a substitute
    for a production-grade digital signature scheme (e.g. Ed25519/RSA
    with a proper PKI).
    """
    canonical = json.dumps(report_body, sort_keys=True, default=str).encode("utf-8")
    keyed_material = settings.SECRET_KEY.encode("utf-8") + canonical
    return hashlib.sha256(keyed_material).hexdigest()


def compile_report(readings: list, reporting_period: str = None) -> dict:
    """
    Compiles a full ESG climate footprint report from a list of IoT
    sensor readings (as produced by iot.sensor_simulator).

    Args:
        readings: list of dicts, each containing at least 'co2_ppm' and
                  'temperature_c' keys.
        reporting_period: optional label for the reporting window
                           (defaults to current UTC date).

    Returns:
        dict: full ESG report including footprint statistics, a mock
              cryptographic signature, and the blockchain block metadata
              the report was anchored to.
    """
    reporting_period = reporting_period or datetime.now(timezone.utc).strftime("%Y-%m")

    if not readings:
        avg_co2 = 0.0
        avg_temp = 0.0
        sample_count = 0
    else:
        avg_co2 = round(sum(r.get("co2_ppm", 0) for r in readings) / len(readings), 2)
        avg_temp = round(sum(r.get("temperature_c", 0) for r in readings) / len(readings), 2)
        sample_count = len(readings)

    # Illustrative derived footprint metrics
    estimated_tons_captured_month = round(
        max(0.0, (450 - avg_co2)) * 3.5 + sample_count * 12.7, 2
    )
    energy_consumed_kwh = round(
        estimated_tons_captured_month * _FACILITY_ENERGY_KWH_PER_TON_CAPTURED, 2
    )
    embodied_emissions_kg = round(
        energy_consumed_kwh * _GRID_CARBON_INTENSITY_KG_PER_KWH, 2
    )
    net_carbon_benefit_tons = round(
        estimated_tons_captured_month - (embodied_emissions_kg / 1000.0), 2
    )

    report_body = {
        "platform": settings.PLATFORM_NAME,
        "organization": settings.ORG_NAME,
        "reporting_period": reporting_period,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample_count": sample_count,
        "average_co2_ppm": avg_co2,
        "average_temperature_c": avg_temp,
        "estimated_tons_captured_month": estimated_tons_captured_month,
        "facility_energy_consumed_kwh": energy_consumed_kwh,
        "embodied_emissions_kg_co2e": embodied_emissions_kg,
        "net_carbon_benefit_tons_co2e": net_carbon_benefit_tons,
    }

    signature = _compute_signature(report_body)
    block_metadata = sign_payload(json.dumps(report_body, sort_keys=True, default=str))

    full_report = {
        **report_body,
        "crypto_signature_sha256": signature,
        "ledger_block_index": block_metadata["index"],
        "ledger_block_hash": block_metadata["hash"],
        "ledger_previous_hash": block_metadata["previous_hash"],
    }

    _logger.info(
        f"ESG report compiled for period={reporting_period} | "
        f"net_benefit={net_carbon_benefit_tons}t CO2e | "
        f"ledger_block={block_metadata['index']} | "
        f"signature={signature[:16]}..."
    )

    return full_report


def verify_report_signature(report: dict) -> bool:
    """
    Re-derives the signature over a report's body fields and compares it
    to the stored signature, demonstrating tamper-evidence verification.
    """
    body_fields = {
        k: v
        for k, v in report.items()
        if k not in (
            "crypto_signature_sha256",
            "ledger_block_index",
            "ledger_block_hash",
            "ledger_previous_hash",
        )
    }
    recomputed = _compute_signature(body_fields)
    is_valid = recomputed == report.get("crypto_signature_sha256")
    if not is_valid:
        _logger.critical(
            "ESG report signature verification FAILED - possible tampering detected "
            f"on ledger_block_index={report.get('ledger_block_index')}"
        )
    return is_valid
