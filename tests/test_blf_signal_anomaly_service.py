from types import SimpleNamespace

from services.blf_signal_anomaly_service import BlfSignalAnomalyService


def message(timestamp, signals, arbitration_id=0x123, channel=7):
    return SimpleNamespace(
        timestamp=timestamp,
        signals=signals,
        arbitration_id=arbitration_id,
        channel=channel,
        message_name="TestMessage",
    )


def test_detects_active_fault_and_recovery() -> None:
    messages = [
        message(1.0, {"BMS_IsolationFault": "no_fault"}),
        message(2.0, {"BMS_IsolationFault": "fault_active"}),
        message(3.0, {"BMS_IsolationFault": "fault_active"}),
        message(4.0, {"BMS_IsolationFault": "no_fault"}),
    ]
    result = BlfSignalAnomalyService().analyze(messages)
    finding = result["findings"][0]
    assert result["fault_count"] == 1
    assert finding["occurrences"] == 2
    assert finding["recovered"] is True
    assert finding["arbitration_id"] == 0x123
    assert finding["value_counts"] == {"fault_active": 2, "no_fault": 2}


def test_does_not_flag_normal_fault_signal() -> None:
    messages = [
        message(1.0, {"HV_InterlockFault": "no_fault"}),
        message(2.0, {"HV_InterlockFault": "no_fault"}),
    ]
    result = BlfSignalAnomalyService().analyze(messages)
    assert result["candidate_signals"] == 1
    assert result["findings"] == []


def test_reports_unavailable_state_as_warning() -> None:
    messages = [
        message(1.0, {"BatteryWarningStatus": "SNA"}),
        message(2.0, {"BatteryWarningStatus": "SNA"}),
    ]
    result = BlfSignalAnomalyService().analyze(messages)
    assert result["warning_count"] == 1
    assert result["findings"][0]["severity"] == "WARNING"


def test_numeric_fault_signal_zero_is_normal_nonzero_is_abnormal() -> None:
    messages = [
        message(1.0, {"DCDC_ErrorFlag": 0}),
        message(2.0, {"DCDC_ErrorFlag": 1}),
    ]
    result = BlfSignalAnomalyService().analyze(messages)
    assert result["fault_count"] == 1
    assert result["findings"][0]["first_value"] == 1


def test_german_negative_states_are_normal() -> None:
    service = BlfSignalAnomalyService()
    values = (
        "keine_Warnung",
        "Keine_Warnung",
        "keine_Vorwarnung",
        "Tuerwarnung_nicht_aktiv",
        "keine_Anforderung_Warnlampe",
        "Kein HV Fehler am HV Heizer erkannt",
        "Kein HV Fehler am EKK erkannt",
        "KeinFehler",
        "kein_KD_Fehler",
        "kein_Sammelfehler",
        "inaktiv",
    )
    assert all(service.classify_value(value) == "NORMAL" for value in values)


def test_german_active_fault_and_invalid_states() -> None:
    service = BlfSignalAnomalyService()
    assert service.classify_value("Fehler") == "ABNORMAL"
    assert service.classify_value("Störung") == "ABNORMAL"
    assert service.classify_value("ungueltig") == "UNAVAILABLE"


def test_can_id_fallback_fields() -> None:
    service = BlfSignalAnomalyService()
    decoded = SimpleNamespace(
        timestamp=1.0,
        signals={"KL_Fehler_HV_Heizer": "Fehler"},
        can_id=0x5E7,
        channel=7,
        message_name="Klima_EV_03",
    )
    result = service.analyze([decoded])
    assert result["findings"][0]["arbitration_id"] == 0x5E7
