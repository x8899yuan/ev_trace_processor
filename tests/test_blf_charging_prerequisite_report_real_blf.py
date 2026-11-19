from pathlib import Path


REPORT_DIR = Path(r"reports\blf")
REPORT_PATTERN = "blf_case_summary_*.txt"


def _latest_report() -> Path:
    reports = list(REPORT_DIR.glob(REPORT_PATTERN))
    assert reports, f"No timestamped BLF case summary found: {REPORT_DIR / REPORT_PATTERN}"
    return max(reports, key=lambda path: path.stat().st_mtime)


def test_blf_case_summary_contains_charging_prerequisite_assessment() -> None:
    report_file = _latest_report()
    report = report_file.read_text(encoding="utf-8")

    expected = [
        "Charging Prerequisite Assessment",
        "kein_Stecker_erkannt",
        "Stby_Ladevorbed_nicht_erfuellt",
        "Root cause remains unconfirmed.",
    ]

    for text in expected:
        assert text in report, f"Missing prerequisite-report evidence: {text}"
