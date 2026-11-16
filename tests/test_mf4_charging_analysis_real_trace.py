from pathlib import Path

from services.mf4_charging_analysis_service import Mf4ChargingAnalysisService


MF4_FILE = Path(r"data\MF4\VW31666_0173_20260508_140000h_Trace.MF4")


def test_mf4_charging_analysis_real_trace() -> None:
    assert MF4_FILE.exists(), f"MF4 file not found: {MF4_FILE}"

    result = Mf4ChargingAnalysisService().analyze(MF4_FILE)

    assert result["charging_progression"] == "NOT_OBSERVED"
    assert result["connector_recognition"] == "NOT_RECOGNIZED"
    assert result["control_pilot_recognition"] == "NOT_ESTABLISHED"
    assert result["cp_fault_observed"] is False
    assert result["root_cause_status"] == "UNCONFIRMED"

    findings = result["findings"]
    assert "kein_Stecker_erkannt" in findings["connector_a"]["unique_values"]
    assert "kein_Stecker_erkannt" in findings["connector_b"]["unique_values"]
    assert "A" in findings["cp_state_a"]["unique_values"]
    assert "kein_Zustand_erkannt" in findings["cp_state_b"]["unique_values"]
    assert "Laden_nicht_angefordert" in findings["charge_request"]["unique_values"]
    assert "Kein_Laden_aktiv" in findings["active_charge_type"]["unique_values"]
    assert "nicht_ladebereit" in findings["vehicle_ready_plc"]["unique_values"]
    assert findings["connector_a"]["invalid_timestamp_count"] > 0
    assert findings["connector_a"]["valid_last_timestamp"] is not None
