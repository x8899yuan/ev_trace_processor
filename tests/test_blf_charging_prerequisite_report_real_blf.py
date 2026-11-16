from pathlib import Path


REPORT_FILE = Path(r"reports\blf\blf_case_summary.txt")


def test_blf_case_summary_contains_charging_prerequisite_assessment() -> None:
    assert REPORT_FILE.exists(), f"Report file not found: {REPORT_FILE}"

    report = REPORT_FILE.read_text(encoding="utf-8")

    expected = [
        "Charging Prerequisite Assessment",
        "kein_Stecker_erkannt",
        "Stby_Ladevorbed_nicht_erfuellt",
        "Root cause remains unconfirmed.",
    ]

    for text in expected:
        assert text in report, f"Missing prerequisite-report evidence: {text}"
