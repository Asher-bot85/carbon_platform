"""
iot/thingsboard_client.py

Publishes simulated (or real) sensor telemetry to a ThingsBoard instance
over MQTT, using each device's access token for authentication.

DESIGN: This module is strictly fire-and-forget. publish_fleet() spawns
one background daemon thread per reading and returns immediately without
waiting for any network I/O to complete. This guarantees it can NEVER
block the calling Streamlit thread, regardless of network conditions,
DNS issues, or a slow/unreachable ThingsBoard broker. Any failures are
logged asynchronously from the background thread itself.

NOTE: THINGSBOARD_HOST is set to the ThingsBoard container's fixed IP on
the minikube Docker network (192.168.49.100). If running on kind instead
of minikube, this must be changed back to the kind network's IP
(typically 172.18.0.100).
"""

import json
import threading

import paho.mqtt.publish as mqtt_publish

from config.audit import AuditLogger

_logger = AuditLogger(source="ThingsBoardClient")

THINGSBOARD_HOST = "192.168.49.100"   # ThingsBoard container's fixed IP on the minikube Docker network
THINGSBOARD_PORT = 1883

# Map each simulated sensor_id to its ThingsBoard device access token
DEVICE_TOKENS = {
    "CC-01": "8dw1pXyaenV8bpgQxuaa",
    "CC-02": "JRW29OrRby6F61BWmBjP",
    "CC-03": "SAR6Pd2ag4e1EqNwbLpa",
    "CC-04": "qo0dFcUsC1wBT0DTInXY",
    "CC-05": "4ZOEFL4B7wOJmAeE1D5c",
    "CC-06": "SIlREGgsm7JVL4OlFG9L",
}

# Dedicated device used purely to surface security alarms in ThingsBoard's
# native Alarms UI.
SECURITY_MONITOR_TOKEN = "lPBrRjvTwXWs1ZVV4Zo1"


def _publish_worker(sensor_id: str, token: str, payload: str):
    """
    Runs entirely in a background daemon thread. Whatever happens here
    (success, failure, hang, timeout) has zero effect on the caller,
    since nothing ever waits on this thread.
    """
    try:
        mqtt_publish.single(
            "v1/devices/me/telemetry",
            payload=payload,
            hostname=THINGSBOARD_HOST,
            port=THINGSBOARD_PORT,
            auth={"username": token},
        )
        _logger.info(f"Published telemetry to ThingsBoard for {sensor_id}")
    except Exception as exc:
        _logger.warning(f"Failed to publish to ThingsBoard for {sensor_id}: {exc}")


def publish_reading(reading: dict) -> bool:
    """
    Fires off a background publish for a single reading and returns
    immediately. Always returns True (meaning "attempt dispatched"),
    since success/failure is only knowable asynchronously and is logged
    separately - this function never blocks waiting for a result.
    """
    sensor_id = reading.get("sensor_id")
    token = DEVICE_TOKENS.get(sensor_id)
    if not token:
        _logger.warning(f"No ThingsBoard token configured for sensor_id={sensor_id}")
        return False

    payload = json.dumps({
        "co2_ppm": reading["co2_ppm"],
        "temperature_c": reading["temperature_c"],
        "humidity_pct": reading["humidity_pct"],
        "pressure_kpa": reading["pressure_kpa"],
        "status": reading["status"],
    })

    thread = threading.Thread(
        target=_publish_worker,
        args=(sensor_id, token, payload),
        daemon=True,
    )
    thread.start()
    return True


def publish_fleet(readings: list) -> int:
    """
    Dispatches a background publish attempt for every reading in the
    fleet. Returns the count of dispatched attempts (not confirmed
    successes - those are logged asynchronously). This function itself
    returns almost instantly regardless of fleet size or network state.
    """
    dispatched_count = 0
    for reading in readings:
        if publish_reading(reading):
            dispatched_count += 1
    return dispatched_count


def publish_security_alert(scenario: str, category: str, verdict: str) -> bool:
    """
    Publishes a security_alert telemetry point to the dedicated
    OT-Security-Monitor device in ThingsBoard. That device's alarm rule
    (security_alert == true) automatically raises a visible CRITICAL
    alarm in ThingsBoard's Alarms UI. Fire-and-forget, same as all other
    publish functions in this module - never blocks the caller.
    """
    if SECURITY_MONITOR_TOKEN == "PASTE_OT_SECURITY_MONITOR_TOKEN_HERE":
        _logger.warning("SECURITY_MONITOR_TOKEN not configured - skipping alarm publish")
        return False

    payload = json.dumps({
        "security_alert": True,
        "scenario": scenario,
        "category": category,
        "verdict": verdict,
    })

    thread = threading.Thread(
        target=_publish_worker,
        args=("OT-Security-Monitor", SECURITY_MONITOR_TOKEN, payload),
        daemon=True,
    )
    thread.start()
    return True