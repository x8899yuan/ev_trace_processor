from services.asc_charging_inspection_report_service import AscChargingInspectionReportService


def test_report_contains_assessment_timelines_and_fault_boundary(tmp_path):
    analysis = {
        "source_file": "sample.asc",
        "classification": "INTERFACE_NOT_ESTABLISHED",
        "charging_progression": "NOT_OBSERVED",
        "connector_recognition": "NOT_RECOGNIZED",
        "control_pilot_recognition": "NOT_ESTABLISHED",
        "charging_request": "NOT_OBSERVED",
        "charging_workflow": "PREREQUISITES_NOT_MET",
        "root_cause_status": "UNCONFIRMED",
        "target_signal_count": 2,
        "target_sample_count": 3,
        "engineering_conclusion": "The charging interface was not established.",
        "signals": {
            "HVLM_CP_State_A": {
                "sample_count": 2,
                "first_timestamp": 1.0,
                "last_timestamp": 2.0,
                "first_value": "A",
                "last_value": "B",
                "unique_values": ["A", "B"],
                "transition_count": 1,
                "transitions": [
                    {"timestamp": 1.0, "value": "A", "channel": 1, "arbitration_id": 0x123, "message_name": "HVLM"},
                    {"timestamp": 2.0, "value": "B", "channel": 1, "arbitration_id": 0x123, "message_name": "HVLM"},
                ],
            }
        },
        "heater_fault_analysis": {
            "sample_count": 1,
            "fault_observed": True,
            "fault_interval_count": 1,
            "active_at_trace_end": False,
            "charging_causal_status": "UNCONFIRMED",
            "intervals": [{"start_timestamp": 3.0, "end_timestamp": 4.0}],
        },
        "evidence_limitations": ["Observed state agreement does not establish physical root cause."],
    }
    path = AscChargingInspectionReportService().generate(analysis, tmp_path / "report.txt")
    text = path.read_text(encoding="utf-8")
    assert "Classification: INTERFACE_NOT_ESTABLISHED" in text
    assert "Control-pilot recognition: NOT_ESTABLISHED" in text
    assert "HVLM_CP_State_A" in text
    assert "1.000000 | A | channel=1 | can_id=0x123 | message=HVLM" in text
    assert "State transitions: 1" in text
    assert "Fault observed: YES" in text
    assert "Charging causal status: UNCONFIRMED" in text
    assert "Interval 1: 3.000000 -> 4.000000" in text
