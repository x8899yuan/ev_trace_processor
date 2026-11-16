from pathlib import Path

from services.session_evidence_adapter import TestSessionEvidenceAdapter
from services.session_summary_service import TestSessionSummaryService


OUTPUT_FILE = Path(r"reports\test_session_summary.txt")


def test_four_trace_session_summary_integration() -> None:
    session_inputs = TestSessionEvidenceAdapter().build_session_inputs(
        vehicle_identity={
            "vin": "1V2ZZZE81TC000011",
            "status": "CONFIRMED",
            "source": "BLF / VIN_01",
        },
        blf={
            "source_file": r"data\blf\VW31666_0173_20260508_140000h_Trace.blf",
            "charging_progression": "NOT_OBSERVED",
            "connector_recognition": "NOT_RECOGNIZED",
            "control_pilot_recognition": "NOT_ESTABLISHED",
            "root_cause_status": "UNCONFIRMED",
            "fault_findings": ["KL_Fehler_HV_Heizer: FAULT OBSERVED"],
        },
        dlt_analysis={
            "capture": {
                "trace_count": 1,
                "source_files": ["VW31666_0173_20260508_140000h_Trace.dlt"],
                "event_count": 100,
            },
            "finding_category_counts": {"error": 1, "warning": 1},
            "severity_counts": {"ERROR": 2, "WARNING": 3},
        },
        pcap_analysis={
            "capture": {
                "file_name": "vehicle_session.pcap",
                "file_path": r"data\pcap\vehicle_session.pcap",
                "packet_count": 1000,
            },
            "protocol_counts": {"IPv6": 500, "TCP": 400, "UDP": 100},
        },
        din70121={"selected_protocol": "DIN 70121"},
        iso15118_tls={"tls_version": "TLS 1.2"},
        mf4={
            "source_file": r"data\MF4\VW31666_0173_20260508_140000h_Trace.MF4",
            "charging_progression": "NOT_OBSERVED",
            "connector_recognition": "NOT_RECOGNIZED",
            "control_pilot_recognition": "NOT_ESTABLISHED",
            "cp_fault_observed": False,
            "root_cause_status": "UNCONFIRMED",
        },
    )

    output_path = TestSessionSummaryService().save_summary(**session_inputs)
    text = OUTPUT_FILE.read_text(encoding="utf-8")

    assert output_path == OUTPUT_FILE.resolve()
    expected = [
        "VIN: 1V2ZZZE81TC000011",
        "VIN Status: CONFIRMED",
        "VIN Evidence Source: BLF / VIN_01",
        "BLF: ANALYZED | VW31666_0173_20260508_140000h_Trace.blf",
        "DLT: ANALYZED | VW31666_0173_20260508_140000h_Trace.dlt",
        "PCAP: ANALYZED | vehicle_session.pcap",
        "MF4: ANALYZED | VW31666_0173_20260508_140000h_Trace.MF4",
        "ERROR findings: 1",
        "WARNING findings: 1",
        "Severity counts: ERROR=2, WARNING=3",
        "Network communication: OBSERVED",
        "Dominant observed protocol: IPv6",
        "DIN 70121: OBSERVED",
        "DIN 70121 negotiated protocol: DIN 70121",
        "ISO 15118 / TLS: OBSERVED",
        "TLS version: TLS 1.2",
        "The current session evidence independently confirms the same unmet charging prerequisites in both BLF and MF4 evidence.",
        "Evidence strength: SUPPORTED_BY_MULTIPLE_TRACES",
        "Causal status: UNCONFIRMED",
        "Input traces are treated as belonging to the same vehicle and testing session.",
    ]
    for value in expected:
        assert value in text, f"Missing four-trace session evidence: {value}"
    assert "DLT independent VIN evidence" not in text
    assert "PCAP independent VIN evidence" not in text
    assert "MF4 independent VIN evidence" not in text
