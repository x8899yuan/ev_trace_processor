from pathlib import Path

from services.charging_analysis_service import (
    ChargingAnalysisService,
)


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)

DBC_FILE = Path(
    r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)


def test_charging_analysis_real_blf() -> None:

    assert BLF_FILE.exists()
    assert DBC_FILE.exists()

    analysis_service = (
        ChargingAnalysisService()
    )

    results = (
        analysis_service.analyze(
            blf_file=BLF_FILE,
            dbc_file=DBC_FILE,
        )
    )

    print()

    print(
        f"Decoded Messages: "
        f"{results['decoded_messages']}"
    )

    print()

    print(
        "Signal Values"
    )

    print("=" * 80)

    for (
        signal_name,
        value,
    ) in results[
        "signal_values"
    ].items():

        print(
            f"{signal_name}: "
            f"{value}"
        )

    print()

    print(
        "Root Cause Findings"
    )

    print("=" * 80)

    for finding in results[
        "findings"
    ]:

        print(
            f"- {finding}"
        )

    print()

    print(
        "Generated Files"
    )

    print("=" * 80)

    print(
        f"Diagnostic Report: "
        f"{results['diagnostic_report']}"
    )

    print(
        f"Case Summary: "
        f"{results['case_summary']}"
    )

    print()

    diagnostic_report = (
        Path(
            results[
                "diagnostic_report"
            ]
        )
    )

    case_summary = (
        Path(
            results[
                "case_summary"
            ]
        )
    )

    assert (
        diagnostic_report.exists()
    )

    assert (
        case_summary.exists()
    )

    assert (
        results[
            "decoded_messages"
        ] > 0
    )

    assert (
        results[
            "signal_values"
        ]
    )

    assert (
        results[
            "findings"
        ]
    )