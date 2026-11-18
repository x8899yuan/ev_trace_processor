from pathlib import Path

import services.session_summary_service as summary_module
from services.session_summary_service import TestSessionSummaryService


RUN_ID = "20261118111230"


def test_session_summary_blf_mf4_agreement_uses_run_id(tmp_path, monkeypatch):
    monkeypatch.setattr(summary_module, "__file__", str(tmp_path / "services" / "session_summary_service.py"))
    vehicle_identity = {"vin": "1V2ZZZE81TC000011", "status": "CONFIRMED", "source": "BLF / VIN_01"}
    blf = {
        "source_file": r"data\blf\session.blf", "charging_progression": "NOT_OBSERVED",
        "connector_recognition": "NOT_RECOGNIZED", "control_pilot_recognition": "NOT_ESTABLISHED",
        "root_cause_status": "UNCONFIRMED", "fault_findings": ["KL_Fehler_HV_Heizer: FAULT OBSERVED", "Charging causal status: UNCONFIRMED"],
    }
    mf4 = {
        "source_file": r"data\MF4\session.MF4", "charging_progression": "NOT_OBSERVED",
        "connector_recognition": "NOT_RECOGNIZED", "control_pilot_recognition": "NOT_ESTABLISHED",
        "cp_fault_observed": False, "root_cause_status": "UNCONFIRMED",
    }
    output = TestSessionSummaryService().save_summary(vehicle_identity=vehicle_identity, blf=blf, mf4=mf4, run_id=RUN_ID)
    expected = (tmp_path / "reports" / f"session_summary_{RUN_ID}.txt").resolve()
    assert output == expected
    text = output.read_text(encoding="utf-8")
    for value in (
        "VIN: 1V2ZZZE81TC000011", "BLF: ANALYZED | session.blf", "MF4: ANALYZED | session.MF4",
        "KL_Fehler_HV_Heizer (HV heater fault): FAULT OBSERVED",
        "Evidence strength: SUPPORTED_BY_MULTIPLE_TRACES", "Explicit CP fault observed: NO",
    ):
        assert value in text
