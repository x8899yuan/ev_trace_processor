from pathlib import Path

from main import main


EVENT_REPORT_FILE = Path(
    r"reports\charging\charging_event_report.txt"
)

EVENT_SUMMARY_FILE = Path(
    r"reports\charging\charging_event_summary.txt"
)

REPORT_FILE = Path(
    r"reports\charging\charging_diagnostic_report.txt"
)

SUMMARY_FILE = Path(
    r"reports\charging\charging_case_summary.txt"
)


def test_main_real_blf() -> None:
    main()

    assert EVENT_REPORT_FILE.exists()
    assert EVENT_SUMMARY_FILE.exists()
    assert REPORT_FILE.exists()
    assert SUMMARY_FILE.exists()

    event_report_content = (
        EVENT_REPORT_FILE.read_text(
            encoding="utf-8"
        )
    )

    event_summary_content = (
        EVENT_SUMMARY_FILE.read_text(
            encoding="utf-8"
        )
    )

    report_content = (
        REPORT_FILE.read_text(
            encoding="utf-8"
        )
    )

    summary_content = (
        SUMMARY_FILE.read_text(
            encoding="utf-8"
        )
    )

    print()
    print("=" * 80)
    print("EVENT REPORT")
    print("=" * 80)
    print()
    print(event_report_content)

    print()
    print("=" * 80)
    print("EVENT SUMMARY")
    print("=" * 80)
    print()
    print(event_summary_content)

    print()
    print("=" * 80)
    print("DIAGNOSTIC REPORT")
    print("=" * 80)
    print()
    print(report_content)

    print()
    print("=" * 80)
    print("CASE SUMMARY")
    print("=" * 80)
    print()
    print(summary_content)

    assert (
        "CHARGING EVENT REPORT"
        in event_report_content
    )

    assert (
        "Charging Event Summary"
        in event_summary_content
    )

    assert (
        "CHARGING DIAGNOSTIC REPORT"
        in report_content
    )

    assert (
        "ENGINEERING CONCLUSION"
        in report_content
    )

    assert (
        "CHARGING CASE SUMMARY"
        in summary_content
    )

    assert (
        "ENGINEERING CONCLUSION"
        in summary_content
    )

    assert (
        "FINAL CONCLUSION"
        in summary_content
    )
