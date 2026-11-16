from pathlib import Path
from types import SimpleNamespace

import services.blf_vehicle_inventory_report_service as report_module
from services.blf_vehicle_inventory_report_service import BlfVehicleInventoryReportService


def test_vehicle_report_includes_validated_anomaly_and_correlation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(report_module, "__file__", str(tmp_path / "services" / "blf_vehicle_inventory_report_service.py"))
    inventory = SimpleNamespace(vehicle=SimpleNamespace(vin="1TESTVIN"), ecus=[])
    anomaly = {
        "fault_count": 1,
        "warning_count": 0,
        "findings": [
            {
                "signal": "KL_Fehler_HV_Heizer",
                "severity": "FAULT",
                "arbitration_id": 0x5E7,
                "message_name": "Klima_EV_03",
                "occurrences": 2425,
                "value_counts": {
                    "Fehler": 2425,
                    "Init": 1515,
                    "Kein HV Fehler am HV Heizer erkannt": 4085,
                },
                "transitions": [{}] * 101,
                "recovered": True,
            }
        ],
    }
    correlation = {
        "fault_signal": "KL_Fehler_HV_Heizer",
        "fault_interval_count": 25,
        "recovered_interval_count": 24,
        "persistent_at_end": True,
        "fault_intervals": [
            {
                "abnormal_samples": 97,
                "charging_progressed_during_fault": False,
                "charging_state": {
                    "HVLM_Ladevorgang_Anf": {"value_at_fault_start": "Laden_nicht_angefordert"},
                    "HVLM_ZustandLadeablauf": {"value_at_fault_start": "Stby_Ladevorbed_nicht_erfuellt"},
                },
            }
        ],
    }
    path = BlfVehicleInventoryReportService().save_report(
        inventory,
        "sample.blf",
        anomaly_analysis=anomaly,
        charging_fault_correlation=correlation,
    )
    text = path.read_text(encoding="utf-8")
    assert "Vehicle Signal Faults / Anomalies" in text
    assert "KL_Fehler_HV_Heizer: FAULT OBSERVED" in text
    assert "CAN ID: 0x5E7" in text
    assert "Charging-to-Fault Correlation" in text
    assert "Fault intervals: 25" in text
    assert "Recovered intervals: 24" in text
    assert "Persistent at trace end: YES" in text
    assert "Causal status: UNCONFIRMED" in text
    assert "does not establish the fault as the charging root cause" in text
