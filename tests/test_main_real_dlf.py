from pathlib import Path

from main import main


def test_main_real_blf():
    project_root = Path(__file__).resolve().parent.parent

    blf_file = (
        project_root
        / "data"
        / "VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
    )

    dbc_file = (
        project_root
        / "data"
        / "E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
    )

    assert blf_file.exists(), f"Missing BLF file: {blf_file}"
    assert dbc_file.exists(), f"Missing DBC file: {dbc_file}"

    result = main(
        blf_path=str(blf_file),
        dbc_path=str(dbc_file),
    )

    assert result is not None

    assert "signal_catalog" in result
    assert "sessions" in result
    assert "timeline" in result
    assert "events" in result
    assert "event_report" in result
    assert "event_summary" in result
    assert "diagnostics" in result
    assert "root_cause" in result
    assert "diagnostic_report" in result
    assert "case_summary" in result

    assert result["signal_catalog"] is not None
    assert result["event_summary"] is not None
    assert result["diagnostic_report"] is not None
    assert result["case_summary"] is not None

    print()
    print("=" * 80)
    print("EVENT SUMMARY")
    print("=" * 80)
    print(result["event_summary"])

    print()
    print("=" * 80)
    print("DIAGNOSTIC REPORT")
    print("=" * 80)
    print(result["diagnostic_report"])

    print()
    print("=" * 80)
    print("CASE SUMMARY")
    print("=" * 80)
    print(result["case_summary"])