from pathlib import Path

from services.asc_dbc_inspection_report_service import AscDbcInspectionReportService


def test_inspection_report_summarizes_coverage_and_engineering_signals(tmp_path):
    analysis = {
        "source_file": "sample.asc",
        "message_count": 100,
        "matched_message_count": 80,
        "decoded_message_count": 75,
        "decode_failure_count": 5,
        "decoded_signal_count": 4,
        "unique_decoded_message_count": 2,
        "unique_decoded_signal_count": 3,
        "message_name_counts": {"VIN_Message": 2, "Charging": 1},
        "unmatched_can_ids": [{"hex_id": "0x777", "count": 20}],
        "decode_failure_can_ids": [{"hex_id": "0x123", "count": 5}],
        "signal_samples": [
            {"signal_name": "VIN_01", "value": "TESTVIN123"},
            {"signal_name": "VIN_01", "value": "TESTVIN123"},
            {"signal_name": "HVLM_CP_State_A", "value": "A"},
            {"signal_name": "HVLM_Ladevorgang_Anf", "value": "Laden_nicht_angefordert"},
        ],
    }
    path = AscDbcInspectionReportService().generate(analysis, tmp_path / "inspection.txt")
    text = path.read_text(encoding="utf-8")
    assert "DBC match coverage: 80.00%" in text
    assert "Decode success among matched: 93.75%" in text
    assert "VIN_01: OBSERVED | samples=2" in text
    assert "HVLM_CP_State_A: OBSERVED | samples=1" in text
    assert "HVLM_Ladevorgang_Anf: OBSERVED | samples=1" in text
    assert "Observed decoded VIN_01 values: TESTVIN123" in text
    assert "Control Pilot state evidence: AVAILABLE" in text
    assert "Charging request evidence: AVAILABLE" in text


def test_inspection_report_does_not_claim_missing_vin(tmp_path):
    analysis = {
        "source_file": "sample.asc",
        "message_count": 0,
        "matched_message_count": 0,
        "decoded_message_count": 0,
        "decode_failure_count": 0,
        "signal_samples": [],
    }
    path = AscDbcInspectionReportService().generate(analysis, tmp_path / "inspection.txt")
    text = path.read_text(encoding="utf-8")
    assert "VIN_01 was not independently decoded from the ASC evidence." in text
    assert "DBC match coverage: 0.00%" in text
    assert "Charging request evidence: NOT_OBSERVED" in text
