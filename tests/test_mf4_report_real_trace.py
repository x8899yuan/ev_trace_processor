from pathlib import Path

import pytest

from services.mf4_charging_analysis_service import Mf4ChargingAnalysisService
from services.mf4_report_service import Mf4ReportService


MF4_DIR = Path("data") / "MF4"
REPORT_DIR = Path("reports") / "mf4"


def _discover_mf4_file():
    files = sorted(path for path in MF4_DIR.iterdir() if path.is_file() and path.suffix.lower() == ".mf4") if MF4_DIR.exists() else []
    if not files:
        pytest.skip(f"No MF4 real-trace fixture found under {MF4_DIR}")
    return files[0]


def test_mf4_report_real_trace():
    mf4_file = _discover_mf4_file()
    analysis = Mf4ChargingAnalysisService().analyze(mf4_file)
    output_path = Mf4ReportService().save_report(analysis)
    summary_path = REPORT_DIR / "mf4_case_summary.txt"
    assert output_path.exists()
    assert summary_path.exists()
    analysis_text = output_path.read_text(encoding="utf-8")
    summary_text = summary_path.read_text(encoding="utf-8")
    assert analysis_text == summary_text
    assert f"MF4 Source: {mf4_file.name}" in summary_text
    for text in ("MF4 Engineering Analysis", "Charging Prerequisite Assessment", "Supporting MF4 Evidence", "Engineering Interpretation", "Analysis Limitations"):
        assert text in summary_text
    translated = ["kein_Stecker_erkannt", "CP_nicht_erkannt", "kein_Fehler", "nicht_ladebereit", "Laden_nicht_angefordert", "Kein_Laden_aktiv"]
    observed = 0
    for raw in translated:
        lines=[line for line in summary_text.splitlines() if raw in line]
        if lines:
            observed += 1
            assert any("(" in line and ")" in line for line in lines)
    assert observed > 0
