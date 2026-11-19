from pathlib import Path

from services.charging_event_report_service import ChargingEventReportService


def test_report_labels_timestamp_and_adds_relative_time(tmp_path):
    service = ChargingEventReportService()
    service.REPORT_PATH = tmp_path / "charging_event_report.txt"
    path = Path(service.generate_report([
        {"timestamp": 1794406540.554302, "signal": "HVLM_Ladevorgang_Anf", "value": "Laden_nicht_angefordert", "description": "Charging not requested"},
        {"timestamp": 1794406585.838207, "signal": "HVLM_Ladevorgang_Anf", "value": "Laden_nicht_angefordert", "description": "Charging not requested"},
    ]))
    text = path.read_text(encoding="utf-8")
    assert "Observation 1" in text
    assert "Timestamp:     1794406540.554302" in text
    assert "Relative time: +0.000 s" in text
    assert "Relative time: +45.284 s" in text
    assert "Raw value:     Laden_nicht_angefordert" in text
    assert "Meaning:       Charging not requested" in text


def test_report_handles_missing_timestamp(tmp_path):
    service = ChargingEventReportService()
    service.REPORT_PATH = tmp_path / "charging_event_report.txt"
    path = Path(service.generate_report([{"signal": "X", "value": "Y", "description": "Condition"}]))
    text = path.read_text(encoding="utf-8")
    assert "Timestamp:     Unknown" in text
    assert "Relative time: Unknown" in text
