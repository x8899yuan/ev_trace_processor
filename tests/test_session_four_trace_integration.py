from pathlib import Path

import services.session_summary_service as summary_module
from services.session_evidence_adapter import TestSessionEvidenceAdapter
from services.session_summary_service import TestSessionSummaryService


RUN_ID = "20261118113000"


def test_four_trace_session_summary_integration(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(summary_module, "__file__", str(tmp_path / "services" / "session_summary_service.py"))
    session_inputs = TestSessionEvidenceAdapter().build_session_inputs(
        vehicle_identity={"vin": "1V2ZZZE81TC000011", "status": "CONFIRMED", "source": "BLF / VIN_01"},
        blf={"source_file": r"data\blf\session.blf", "charging_progression": "NOT_OBSERVED", "connector_recognition": "NOT_RECOGNIZED", "control_pilot_recognition": "NOT_ESTABLISHED", "root_cause_status": "UNCONFIRMED", "fault_findings": ["KL_Fehler_HV_Heizer: FAULT OBSERVED"]},
        dlt_analysis={"capture": {"trace_count": 1, "source_files": ["session.dlt"], "event_count": 100}, "finding_category_counts": {"error": 1, "warning": 1}, "severity_counts": {"ERROR": 2, "WARNING": 3}},
        pcap_analysis={"capture": {"file_name": "vehicle_session.pcap", "file_path": r"data\pcap\vehicle_session.pcap", "packet_count": 1000}, "protocol_counts": {"IPv6": 500, "TCP": 400, "UDP": 100}},
        din70121={"selected_protocol": "DIN 70121"},
        iso15118_tls={"tls_version": "TLS 1.2"},
        mf4={"source_file": r"data\MF4\session.MF4", "charging_progression": "NOT_OBSERVED", "connector_recognition": "NOT_RECOGNIZED", "control_pilot_recognition": "NOT_ESTABLISHED", "cp_fault_observed": False, "root_cause_status": "UNCONFIRMED"},
    )
    output = TestSessionSummaryService().save_summary(**session_inputs, run_id=RUN_ID)
    expected = (tmp_path / "reports" / f"session_summary_{RUN_ID}.txt").resolve()
    assert output == expected
    text = output.read_text(encoding="utf-8")
    for value in (
        "VIN: 1V2ZZZE81TC000011", "BLF: ANALYZED | session.blf", "DLT: ANALYZED | session.dlt",
        "PCAP: ANALYZED | vehicle_session.pcap", "MF4: ANALYZED | session.MF4",
        "Severity counts: ERROR=2, WARNING=3", "Network communication: OBSERVED",
        "The current session evidence independently confirms the same unmet charging prerequisites in both BLF and MF4 evidence.",
        "Evidence strength: SUPPORTED_BY_MULTIPLE_TRACES", "Causal status: UNCONFIRMED",
    ):
        assert value in text
