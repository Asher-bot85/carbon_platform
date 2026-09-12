"""
iot/sensor_simulator.py

Simulates telemetry from carbon-capture facility IoT sensor nodes and
generates mock asset location logs. No real hardware is involved - this
module produces statistically plausible readings for demo/dashboard
purposes, centered on realistic atmospheric CO2 (~415 ppm ambient
reference) and moderate climate-facility ambient temperature (~15 C).
"""

import random
import uuid
from datetime import datetime, timezone

from config import settings

_SITE_NAMES = [
    "North Ridge Capture Array",
    "Coastal Basin Scrubber Farm",
    "Highland DAC Facility",
    "River Delta Sequestration Site",
    "Prairie Wind DAC Cluster",
    "Alpine Geological Storage Hub",
]

_SITE_COORDINATES = [
    {"lat": 47.6062, "lon": -122.3321},   # Seattle-ish
    {"lat": 29.7604, "lon": -95.3698},    # Houston-ish
    {"lat": 39.7392, "lon": -104.9903},   # Denver-ish
    {"lat": 29.9511, "lon": -90.0715},    # New Orleans-ish
    {"lat": 41.8781, "lon": -87.6298},    # Chicago-ish
    {"lat": 46.8182, "lon": 8.2275},      # Swiss Alps-ish
]


def generate_reading(sensor_id: str = None) -> dict:
    """
    Generates a single simulated IoT telemetry reading.

    Returns:
        dict with keys: sensor_id, timestamp, co2_ppm, temperature_c,
        humidity_pct, pressure_kpa, status
    """
    sensor_id = sensor_id or f"CC-{random.randint(1, settings.DEFAULT_SENSOR_FLEET_SIZE):02d}"

    co2_ppm = round(random.gauss(415, 12), 2)
    temperature_c = round(random.gauss(15, 3), 2)
    humidity_pct = round(random.uniform(35, 70), 1)
    pressure_kpa = round(random.gauss(101.3, 0.6), 2)

    if (
        co2_ppm < settings.CO2_SAFE_LOWER_PPM
        or co2_ppm > settings.CO2_SAFE_UPPER_PPM
        or temperature_c < settings.TEMPERATURE_SAFE_LOWER_C
        or temperature_c > settings.TEMPERATURE_SAFE_UPPER_C
    ):
        status = "CRITICAL"
    elif abs(co2_ppm - 415) > 40 or abs(temperature_c - 15) > 8:
        status = "WARNING"
    else:
        status = "NORMAL"

    return {
        "sensor_id": sensor_id,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "co2_ppm": co2_ppm,
        "temperature_c": temperature_c,
        "humidity_pct": humidity_pct,
        "pressure_kpa": pressure_kpa,
        "status": status,
    }


def generate_fleet_readings(n: int = None) -> list:
    """
    Generates a full fleet of simulated sensor readings, one per sensor
    node, suitable for rendering as a live metrics table.
    """
    n = n or settings.DEFAULT_SENSOR_FLEET_SIZE
    return [generate_reading(sensor_id=f"CC-{i:02d}") for i in range(1, n + 1)]


def generate_asset_locations() -> list:
    """
    Generates simulated facility/asset location log entries, each
    representing a physical carbon-capture site with an estimated
    monthly capture tonnage and operational status.
    """
    assets = []
    for i, name in enumerate(_SITE_NAMES):
        coords = _SITE_COORDINATES[i % len(_SITE_COORDINATES)]
        assets.append(
            {
                "asset_id": f"SITE-{i + 1:03d}",
                "site_name": name,
                "lat": coords["lat"] + random.uniform(-0.05, 0.05),
                "lon": coords["lon"] + random.uniform(-0.05, 0.05),
                "capture_tons_month": round(random.uniform(850, 4200), 1),
                "operational_status": random.choices(
                    ["ONLINE", "ONLINE", "ONLINE", "MAINTENANCE", "DEGRADED"],
                    weights=[5, 5, 5, 2, 1],
                    k=1,
                )[0],
                "last_inspection": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "asset_uuid": str(uuid.uuid4()),
            }
        )
    return assets


def generate_live_log_line() -> str:
    """
    Generates a single free-text operational log line, used to populate
    the "live logs" feed in the Carbon Capture Operations dashboard tab.
    """
    reading = generate_reading()
    templates = [
        f"Sensor {reading['sensor_id']} heartbeat OK | CO2={reading['co2_ppm']}ppm "
        f"Temp={reading['temperature_c']}C Status={reading['status']}",
        f"Scrubber unit on {reading['sensor_id']} completed capture cycle "
        f"({round(random.uniform(1.2, 8.5), 2)} tons CO2 processed)",
        f"Telemetry sync from {reading['sensor_id']} committed to time-series store",
        f"Valve actuator on {reading['sensor_id']} reported nominal pressure "
        f"({reading['pressure_kpa']} kPa)",
        f"Fan array on {reading['sensor_id']} adjusted RPM for ambient humidity "
        f"{reading['humidity_pct']}%",
    ]
    return random.choice(templates)
