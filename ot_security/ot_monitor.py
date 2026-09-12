"""
ot_security/ot_monitor.py

Implements a simplified Purdue Model (Purdue Enterprise Reference
Architecture) zone-compliance checker for OT/ICS network segmentation
governing the carbon-capture control systems.

Purdue Zones modeled:
    Level 0   - Physical Process (sensors, actuators, scrubber hardware)
    Level 1   - Basic Control (PLCs, RTUs)
    Level 2   - Supervisory Control (SCADA / HMI)
    Level 3   - Site Operations (MES, historian)
    Level 3.5 - Industrial DMZ (mandatory buffer zone)
    Level 4   - Business Logistics (corporate IT, ERP)
    Level 5   - Enterprise Network (internet-facing systems)

Core compliance rule enforced: any traffic attempting to cross directly
between the OT zones (Level 0-3) and the IT zones (Level 4-5) WITHOUT
transiting the Industrial DMZ (Level 3.5) is flagged non-compliant, as
this violates standard ICS/OT segmentation best practice (e.g. NIST SP
800-82, IEC 62443).
"""

from config.audit import AuditLogger

_logger = AuditLogger(source="OTMonitor")

PURDUE_ZONES = {
    0: "Physical Process",
    1: "Basic Control",
    2: "Supervisory Control",
    3: "Site Operations",
    3.5: "Industrial DMZ",
    4: "Business Logistics",
    5: "Enterprise Network",
}

_OT_ZONES = {0, 1, 2, 3}
_IT_ZONES = {4, 5}
_DMZ_ZONE = 3.5


def _zone_name(zone: float) -> str:
    return PURDUE_ZONES.get(zone, f"Unknown Zone ({zone})")


def check_zone_compliance(source_zone: float, dest_zone: float) -> dict:
    """
    Evaluates whether direct communication from `source_zone` to
    `dest_zone` complies with Purdue Model segmentation rules.

    Args:
        source_zone: numeric Purdue level of the traffic source
                     (e.g. 1, 2, 3, 3.5, 4, 5)
        dest_zone:   numeric Purdue level of the traffic destination

    Returns:
        dict: {
            "compliant": bool,
            "reason": str,
            "source_zone_name": str,
            "dest_zone_name": str,
            "recommended_path": str or None
        }
    """
    if source_zone not in PURDUE_ZONES or dest_zone not in PURDUE_ZONES:
        result = {
            "compliant": False,
            "reason": "One or both zones are not recognized Purdue Model levels.",
            "source_zone_name": _zone_name(source_zone),
            "dest_zone_name": _zone_name(dest_zone),
            "recommended_path": None,
        }
        _logger.warning(
            f"Unrecognized Purdue zone in compliance check: "
            f"source={source_zone}, dest={dest_zone}"
        )
        return result

    same_zone = source_zone == dest_zone
    if same_zone:
        return {
            "compliant": True,
            "reason": "Traffic remains within the same Purdue zone.",
            "source_zone_name": _zone_name(source_zone),
            "dest_zone_name": _zone_name(dest_zone),
            "recommended_path": None,
        }

    crosses_ot_it_boundary = (
        (source_zone in _OT_ZONES and dest_zone in _IT_ZONES)
        or (source_zone in _IT_ZONES and dest_zone in _OT_ZONES)
    )

    if crosses_ot_it_boundary:
        reason = (
            f"Direct traffic between OT zone '{_zone_name(source_zone)}' and IT zone "
            f"'{_zone_name(dest_zone)}' bypasses the mandatory Industrial DMZ "
            f"(Level 3.5). This violates standard ICS/OT segmentation policy."
        )
        _logger.high(
            f"Non-compliant Purdue traffic detected: {_zone_name(source_zone)} -> "
            f"{_zone_name(dest_zone)} (DMZ bypass)"
        )
        return {
            "compliant": False,
            "reason": reason,
            "source_zone_name": _zone_name(source_zone),
            "dest_zone_name": _zone_name(dest_zone),
            "recommended_path": (
                f"{_zone_name(source_zone)} -> Industrial DMZ (3.5) -> "
                f"{_zone_name(dest_zone)}"
            ),
        }

    # Adjacent-zone or DMZ-mediated traffic is considered compliant
    return {
        "compliant": True,
        "reason": (
            f"Traffic from '{_zone_name(source_zone)}' to '{_zone_name(dest_zone)}' "
            "follows an approved segmentation path."
        ),
        "source_zone_name": _zone_name(source_zone),
        "dest_zone_name": _zone_name(dest_zone),
        "recommended_path": None,
    }


def audit_zone_matrix() -> list:
    """
    Runs check_zone_compliance across every pairwise combination of
    defined Purdue zones and returns the full compliance matrix, used
    to render a summary table in the dashboard.
    """
    zones = sorted(PURDUE_ZONES.keys())
    results = []
    for src in zones:
        for dst in zones:
            if src == dst:
                continue
            results.append(
                {
                    "source_zone": src,
                    "dest_zone": dst,
                    **check_zone_compliance(src, dst),
                }
            )
    return results
