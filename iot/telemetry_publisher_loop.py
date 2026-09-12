"""
iot/telemetry_publisher_loop.py

Standalone, long-running background process that continuously publishes
simulated sensor telemetry to ThingsBoard every PUBLISH_INTERVAL_SECONDS.

This runs completely independently of the Streamlit dashboard - it keeps
all ThingsBoard devices (CC-01 through CC-06) showing as "Active" for as
long as this process keeps running, regardless of whether anyone has the
dashboard open or is clicking the manual refresh button.

Also sends a periodic security_alert=False heartbeat to the dedicated
OT-Security-Monitor device, keeping that device Active too between
attack simulation runs (it otherwise only receives telemetry during
attack_sim/attacker.py runs). The heartbeat's False value never matches
the alarm rule's "equals true" condition, so it never triggers a false
alarm - it only keeps the device's Active status alive.

Intended to run as its own Kubernetes Deployment so it survives dashboard
pod restarts and keeps running until explicitly scaled down or the
cluster is torn down.
"""

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone

# Ensure the project root is importable when run directly
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from iot import sensor_simulator                # noqa: E402
from iot import thingsboard_client               # noqa: E402
from config.audit import AuditLogger             # noqa: E402

_logger = AuditLogger(source="TelemetryPublisherLoop")

PUBLISH_INTERVAL_SECONDS = 30


def _publish_security_monitor_heartbeat():
    """
    Sends a security_alert=False heartbeat to the OT-Security-Monitor
    device so it keeps showing as Active in ThingsBoard between attack
    runs. Fire-and-forget, matching thingsboard_client's design.
    """
    if thingsboard_client.SECURITY_MONITOR_TOKEN == "PASTE_OT_SECURITY_MONITOR_TOKEN_HERE":
        return

    heartbeat_payload = json.dumps({"security_alert": False, "heartbeat": True})
    thread = threading.Thread(
        target=thingsboard_client._publish_worker,
        args=("OT-Security-Monitor", thingsboard_client.SECURITY_MONITOR_TOKEN, heartbeat_payload),
        daemon=True,
    )
    thread.start()


def run_forever():
    _logger.info(
        f"Telemetry publisher loop started | interval={PUBLISH_INTERVAL_SECONDS}s"
    )
    print(f"Starting continuous ThingsBoard telemetry publisher (every {PUBLISH_INTERVAL_SECONDS}s)")
    print("This process runs forever until manually stopped.\n")

    cycle = 0
    while True:
        cycle += 1
        readings = sensor_simulator.generate_fleet_readings()
        dispatched = thingsboard_client.publish_fleet(readings)
        _publish_security_monitor_heartbeat()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"[{timestamp}] Cycle {cycle}: dispatched {dispatched} telemetry publish(es) + security monitor heartbeat")
        time.sleep(PUBLISH_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_forever()
