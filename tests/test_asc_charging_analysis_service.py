from services.asc_charging_analysis_service import AscChargingAnalysisService


def sample(timestamp, signal, value):
    return {"timestamp": timestamp, "signal_name": signal, "value": value, "channel": 1, "arbitration_id": 1, "message_name": "M"}


def test_interface_not_established_classification_uses_timelines():
    result = AscChargingAnalysisService().analyze({"signal_samples": [
        sample(1.0, "HVLM_Steckerstatus_A", "kein_Stecker_erkannt"),
        sample(1.1, "HVLM_CP_State_A", "A"),
        sample(1.2, "HVLM_Ladevorgang_Anf", "Laden_nicht_angefordert"),
        sample(1.3, "HVLM_ZustandLadeablauf", "Stby_Ladevorbed_nicht_erfuellt"),
    ]})
    assert result["classification"] == "INTERFACE_NOT_ESTABLISHED"
    assert result["charging_progression"] == "NOT_OBSERVED"
    assert result["connector_recognition"] == "NOT_RECOGNIZED"
    assert result["control_pilot_recognition"] == "NOT_ESTABLISHED"
    assert result["root_cause_status"] == "UNCONFIRMED"


def test_completed_sequence_wins_over_initial_states():
    result = AscChargingAnalysisService().analyze({"signal_samples": [
        sample(1.0, "HVLM_Steckerstatus_A", "kein_Stecker_erkannt"),
        sample(2.0, "HVLM_Steckerstatus_A", "Stecker_erkannt"),
        sample(1.0, "HVLM_CP_State_A", "A"),
        sample(2.0, "HVLM_CP_State_A", "B"),
        sample(3.0, "HVLM_CP_State_A", "C"),
        sample(3.0, "HVLM_Ladevorgang_Anf", "Laden_angefordert"),
        sample(4.0, "HVLM_ZustandLadeablauf", "Charging_completed"),
    ]})
    assert result["classification"] == "COMPLETED"
    assert result["charging_progression"] == "COMPLETED"
    assert result["connector_recognition"] == "RECOGNIZED"
    assert result["control_pilot_recognition"] == "ESTABLISHED"
    assert result["signals"]["HVLM_CP_State_A"]["transition_count"] == 2


def test_heater_fault_intervals_do_not_claim_charging_causality():
    result = AscChargingAnalysisService().analyze({"signal_samples": [
        sample(1.0, "KL_Fehler_HV_Heizer", "Kein HV Fehler am HV Heizer erkannt"),
        sample(2.0, "KL_Fehler_HV_Heizer", "Fehler"),
        sample(3.0, "KL_Fehler_HV_Heizer", "Fehler"),
        sample(4.0, "KL_Fehler_HV_Heizer", "Kein HV Fehler am HV Heizer erkannt"),
    ]})
    heater = result["heater_fault_analysis"]
    assert heater["fault_observed"] is True
    assert heater["fault_interval_count"] == 1
    assert heater["intervals"] == [{"start_timestamp": 2.0, "end_timestamp": 4.0}]
    assert heater["charging_causal_status"] == "UNCONFIRMED"


def test_missing_target_signals_is_insufficient_evidence():
    result = AscChargingAnalysisService().analyze({"signal_samples": []})
    assert result["classification"] == "INSUFFICIENT_EVIDENCE"
    assert result["charging_progression"] == "INDETERMINATE"
