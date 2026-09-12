"""
Smoke tests for carbon_platform1.
These confirm the core modules import cleanly. Expand this file with real
unit tests for app.py, blockchain/ledger.py, esg/reporter.py, etc. as you
build out coverage.
"""


def test_config_settings_imports():
    from config import settings  # noqa: F401


def test_esg_reporter_imports():
    from esg import reporter  # noqa: F401


def test_blockchain_ledger_imports():
    from blockchain import ledger  # noqa: F401


def test_iot_sensor_simulator_imports():
    from iot import sensor_simulator  # noqa: F401


def test_security_ids_imports():
    from security import ids  # noqa: F401
