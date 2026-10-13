from pathlib import Path

from services.charging_analysis_service import (
    ChargingAnalysisService,
)


def main() -> None:
    print("=" * 80)
    print("EV TRACE PROCESSOR")
    print("=" * 80)
    print()

    blf_file = Path(
        r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
    )

    dbc_file = Path(
        r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
    )

    if not blf_file.exists():
        print(
            f"BLF file not found: {blf_file}"
        )
        return

    if not dbc_file.exists():
        print(
            f"DBC file not found: {dbc_file}"
        )
        return

    analysis_service = (
        ChargingAnalysisService()
    )

    results = (
        analysis_service.analyze(
            blf_file=blf_file,
            dbc_file=dbc_file,
        )
    )

    print("ANALYSIS RESULTS")
    print("=" * 80)

    print(
        f"Decoded Messages: "
        f"{results['decoded_messages']}"
    )

    print(
        f"Timeline Entries: "
        f"{results['timeline_entries']}"
    )

    print(
        f"Events Detected: "
        f"{results['events_detected']}"
    )

    print()

    print("ROOT CAUSE FINDINGS")
    print("=" * 80)

    for finding in results["findings"]:
        print(f"- {finding}")

    print()
    print("GENERATED REPORTS")
    print("=" * 80)

    print(
        f"Event Report: "
        f"{results['event_report']}"
    )

    print(
        f"Event Summary: "
        f"{results['event_summary']}"
    )

    print(
        f"Diagnostic Report: "
        f"{results['diagnostic_report']}"
    )

    print(
        f"Case Summary: "
        f"{results['case_summary']}"
    )

    print()
    print("PROCESSING COMPLETE")


if __name__ == "__main__":
    main()