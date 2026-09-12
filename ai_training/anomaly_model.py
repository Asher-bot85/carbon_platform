"""
ai_training/anomaly_model.py

Trains a lightweight Isolation Forest anomaly-detection model on
simulated IoT sensor telemetry (CO2, temperature, humidity, pressure)
to identify anomalous carbon-capture facility readings. This provides
a genuine "AI training results" artifact for the platform: the model
is trained fresh each run, and its performance metrics (anomaly rate,
feature importance proxy, sample counts) are surfaced in the dashboard.
"""

import time
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from config.audit import AuditLogger

_logger = AuditLogger(source="AITrainingPipeline")

FEATURE_COLUMNS = ["co2_ppm", "temperature_c", "humidity_pct", "pressure_kpa"]


def train_anomaly_model(readings: list, contamination: float = 0.08) -> dict:
    """
    Trains an Isolation Forest anomaly detector on a list of IoT sensor
    reading dicts (as produced by iot.sensor_simulator).

    Returns a dict of training results: model performance metrics,
    timing, sample counts, and per-sample anomaly labels/scores.
    """
    start_time = time.time()

    df = pd.DataFrame(readings)
    X = df[FEATURE_COLUMNS].values

    X_train, X_test = train_test_split(X, test_size=0.25, random_state=42)

    model = IsolationForest(
        n_estimators=150,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X_train)

    train_predictions = model.predict(X_train)
    test_predictions = model.predict(X_test)

    train_anomaly_count = int(np.sum(train_predictions == -1))
    test_anomaly_count = int(np.sum(test_predictions == -1))

    all_predictions = model.predict(X)
    all_scores = model.decision_function(X)

    df["anomaly_score"] = all_scores
    df["is_anomaly"] = all_predictions == -1

    training_duration = round(time.time() - start_time, 3)

    feature_ranges = {
        col: {
            "min": float(df[col].min()),
            "max": float(df[col].max()),
            "mean": round(float(df[col].mean()), 2),
            "std": round(float(df[col].std()), 2),
        }
        for col in FEATURE_COLUMNS
    }

    results = {
        "model_type": "IsolationForest",
        "n_estimators": 150,
        "contamination_rate": contamination,
        "total_samples": len(readings),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "train_anomalies_detected": train_anomaly_count,
        "test_anomalies_detected": test_anomaly_count,
        "train_anomaly_rate_pct": round((train_anomaly_count / len(X_train)) * 100, 2),
        "test_anomaly_rate_pct": round((test_anomaly_count / len(X_test)) * 100, 2),
        "training_duration_seconds": training_duration,
        "feature_ranges": feature_ranges,
        "flagged_readings": df[df["is_anomaly"]][
            ["sensor_id", "timestamp", "co2_ppm", "temperature_c", "status", "anomaly_score"]
        ].to_dict(orient="records"),
        "all_readings_scored": df[
            ["sensor_id", "timestamp", "co2_ppm", "temperature_c", "humidity_pct", "pressure_kpa", "is_anomaly", "anomaly_score"]
        ].to_dict(orient="records"),
    }

    _logger.info(
        f"AI anomaly-detection model trained | samples={results['total_samples']} | "
        f"test_anomaly_rate={results['test_anomaly_rate_pct']}% | "
        f"duration={training_duration}s"
    )

    if test_anomaly_count > 0:
        _logger.high(
            f"AI model flagged {test_anomaly_count} anomalous sensor reading(s) "
            f"in test set ({results['test_anomaly_rate_pct']}% anomaly rate)"
        )

    return results
