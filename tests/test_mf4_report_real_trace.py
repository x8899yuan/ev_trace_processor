from pathlib import Path

from services.mf4_charging_analysis_service import Mf4ChargingAnalysisService
from services.mf4_report_service import Mf4ReportService


MF4_FILE = Path(r"data\MF4\VW31666_0173_20260508_140000h_Trace.MF4")
REPORT_DIR = Path(r"reports\mf4")
ANALYSIS_REPORT = REPORT_DIR / "mf4_analysis_report.txt"
CASE_SUMMARY = REPORT_DIR / "mf4_case_summary.txt"


def test_mf4_report_real_trace() -> None:
    assert MF4_FILE.exists(), f"MF4 file not found: {MF4_FILE}"

    analysis = Mf4ChargingAnalysisService().analyze(MF4_FILE)
    output_path = Mf4ReportService().save_report(analysis)

    assert output_path == ANALYSIS_REPORT.resolve()
    assert ANALYSIS_REPORT.exists()
    assert CASE_SUMMARY.exists()

    analysis_text = ANALYSIS_REPORT.read_text(encoding="utf-8")
    summary_text = CASE_SUMMARY.read_text(encoding="utf-8")

    assert analysis_text == summary_text

    expected = [
        "MF4 Engineering Analysis",
        "MF4 Source: VW31666_0173_20260508_140000h_Trace.MF4",
        "Charging progression: NOT_OBSERVED",
        "Connector recognition: NOT_RECOGNIZED",
        "Control-pilot recognition: NOT_ESTABLISHED",
        "Explicit CP fault observed: NO",
        "Root cause status: UNCONFIRMED",
        "Charging Prerequisite Assessment",
        "Connector path A: Init, kein_Stecker_erkannt",
        "Connector path B: kein_Stecker_erkannt",
        "Control-pilot path A: A, Init",
        "Control-pilot path B: kein_Zustand_erkannt",
        "General vehicle charging capability: AC_DC_und_Induktiv_Ladebereit",
        "PLC charging readiness: nicht_ladebereit",
        "Charging request: Laden_nicht_angefordert",
        "Active charging mode: Kein_Laden_aktiv",
        "Supporting MF4 Evidence",
        "group=72",
        "Duplicate Channel Observations",
        "Timestamp Quality",
        "Engineering Interpretation",
        "Charging did not become active during the MF4 recording.",
        "The evidence localizes the missing prerequisite to connector/control-pilot recognition",
        "Root cause remains unconfirmed.",
        "Analysis Limitations",
        "This MF4 report is trace-local",
    ]

    for text in expected:
        assert text in summary_text, f"Missing MF4 report evidence: {text}"
