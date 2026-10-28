from pathlib import Path

from services.charging_analysis_service import ChargingAnalysisService


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def find_file(file_name: str) -> Path:
    matches = list(PROJECT_ROOT.rglob(file_name))
    assert matches, f"File not found: {file_name}"
    return matches[0]


def test_main_real_blf() -> None:
    blf_file = find_file(
        "VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
    )
    dbc_file = find_file(
        "E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
    )

    results = ChargingAnalysisService().analyze(
        blf_file=blf_file,
        dbc_file=dbc_file,
    )

    assert results["decoded_messages"] > 0
    assert results["signal_values"]
    assert results["timeline_entries"] > 0
    assert results["events_detected"] > 0
    assert results["findings"]

    event_summary = Path(results["event_summary"])
    case_summary = Path(results["case_summary"])

    assert event_summary.exists()
    assert case_summary.exists()

    diagnostic_report = results["diagnostic_report"]
    assert isinstance(diagnostic_report, str)
    assert "CHARGING DIAGNOSTIC REPORT" in diagnostic_report
