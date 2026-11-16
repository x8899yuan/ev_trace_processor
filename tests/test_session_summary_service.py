from pathlib import Path

from services.session_summary_service import TestSessionSummaryService


OUTPUT_FILE = Path(r"reports\test_session_summary.txt")


def test_test_session_summary_blf_mf4_agreement() -> None:
    vehicle_identity = {
        "vin": "1V2ZZZE81TC000011",
        "status": "CONFIRMED",
        "source": "BLF / VIN_01",
    }
    blf = {
        "source_file": r"data\blf\VW31666_0173_20260508_140000h_Trace.blf",
        "charging_progression": "NOT_OBSERVED",
        "connector_recognition": "NOT_RECOGNIZED",
        "control_pilot_recognition": "NOT_ESTABLISHED",
        "root_cause_status": "UNCONFIRMED",
        "fault_findings": [
            "KL_Fehler_HV_Heizer: FAULT OBSERVED",
            "Charging causal status: UNCONFIRMED",
        ],
    }
    mf4 = {
        "source_file": r"data\MF4\VW31666_0173_20260508_140000h_Trace.MF4",
        "charging_progression": "NOT_OBSERVED",
        "connector_recognition": "NOT_RECOGNIZED",
        "control_pilot_recognition": "NOT_ESTABLISHED",
        "cp_fault_observed": False,
        "root_cause_status": "UNCONFIRMED",
        "findings": {
            "connector_a": "kein_Stecker_erkannt",
            "connector_b": "kein_Stecker_erkannt",
            "cp_state_a": "A",
            "cp_state_b": "kein_Zustand_erkannt",
        },
    }

    output_path = TestSessionSummaryService().save_summary(
        vehicle_identity=vehicle_identity,
        blf=blf,
        mf4=mf4,
    )

    assert output_path == OUTPUT_FILE.resolve()
    text = OUTPUT_FILE.read_text(encoding="utf-8")
    expected = [
        "Vehicle Test Session Engineering Summary",
        "VIN: 1V2ZZZE81TC000011",
        "VIN Status: CONFIRMED",
        "VIN Evidence Source: BLF / VIN_01",
        "BLF: ANALYZED | VW31666_0173_20260508_140000h_Trace.blf",
        "MF4: ANALYZED | VW31666_0173_20260508_140000h_Trace.MF4",
        "Charging progression: NOT_OBSERVED",
        "Connector recognition: NOT_RECOGNIZED",
        "Control-pilot recognition: NOT_ESTABLISHED",
        "Root cause status: UNCONFIRMED",
        "Explicit CP fault observed: NO",
        "KL_Fehler_HV_Heizer (HV heater fault): FAULT OBSERVED",
        "The current session evidence independently confirms the same unmet charging prerequisites in both BLF and MF4 evidence.",
        "Evidence strength: SUPPORTED_BY_MULTIPLE_TRACES",
        "Causal status: UNCONFIRMED",
        "Input traces are treated as belonging to the same vehicle and testing session.",
    ]
    for value in expected:
        assert value in text, f"Missing session-summary evidence: {value}"

    assert "DLT independent VIN evidence" not in text
    assert "PCAP independent VIN evidence" not in text
    assert "MF4 independent VIN evidence" not in text
