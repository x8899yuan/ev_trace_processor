from services.charging_case_summary_service import ChargingCaseSummaryService


def _generate(tmp_path, signals, findings):
    path = ChargingCaseSummaryService().generate_summary(signals, findings, tmp_path)
    return path.read_text(encoding="utf-8")


def test_interface_not_established_summary_is_evidence_driven(tmp_path):
    report = _generate(tmp_path, {"HVLM_Steckerstatus_A": "kein_Stecker_erkannt", "HVLM_CP_State_A": "A", "HVLM_CP_MaxStrom_A": "0.0", "HVLM_Ladevorgang_Anf": "Laden_nicht_angefordert", "HVLM_ZustandLadeablauf": "Stby_Ladevorbed_nicht_erfuellt"}, ["Charging was not requested."])
    assert "Charging did not progress beyond the interface/prerequisite stage." in report
    assert "Charging remained at the interface/prerequisite stage and did not start." in report
    assert "Control Pilot state:               A" in report
    assert "Charging completed:                Not applicable" in report
    assert "Meaning: Maximum current indicated by the Control Pilot: 0.0 A" in report
    assert "No engineering conclusion available" not in report


def test_requested_but_prerequisites_not_met(tmp_path):
    report = _generate(tmp_path, {"HVLM_Steckerstatus_A": "Stecker_erkannt", "HVLM_CP_State_A": "B", "HVLM_Ladevorgang_Anf": "Laden_angefordert", "HVLM_ZustandLadeablauf": "Ladevorbed_nicht_erfuellt"}, [])
    assert "A charging request was observed, but charging prerequisites were not satisfied." in report
    assert "Charging was requested but remained blocked by unsatisfied prerequisites." in report


def test_completed_charging_does_not_report_failure(tmp_path):
    report = _generate(tmp_path, {"HVLM_Steckerstatus_A": "Stecker_erkannt", "HVLM_CP_State_A": "C", "HVLM_Ladevorgang_Anf": "Laden_angefordert", "HVLM_ZustandLadeablauf": "Charging_completed"}, [])
    assert "The analyzed evidence shows completed charging progression." in report
    assert "A completed charging sequence was observed." in report
    assert "did not start" not in report


def test_no_evidence_is_reported_as_insufficient(tmp_path):
    report = _generate(tmp_path, {}, [])
    assert "do not contain enough charging evidence" in report
    assert "No evidence-supported charging-stage conclusion can be assigned." in report
