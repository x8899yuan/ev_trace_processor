from pathlib import Path

import main as main_module


ANALYSIS_RESULTS = {
    "decoded_messages": 3121,
    "timeline_entries": 6,
    "events_detected": 6,
    "findings": ["Charging permission denied."],
    "event_report": Path("reports/charging/charging_event_report.txt"),
    "event_summary": Path("reports/charging/charging_event_summary.txt"),
    "diagnostic_report": "CHARGING DIAGNOSTIC REPORT",
    "case_summary": Path("reports/charging/charging_case_summary.txt"),
}


class FakeChargingAnalysisService:
    calls = []

    def analyze(self, blf_file, dbc_file):
        self.__class__.calls.append(
            {
                "blf_file": blf_file,
                "dbc_file": dbc_file,
            }
        )
        return ANALYSIS_RESULTS.copy()


def configure_main(monkeypatch, tmp_path):
    blf_file = (
        tmp_path
        / "data"
        / "blf"
        / "VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
    )
    dbc_file = (
        tmp_path
        / "dbc"
        / "E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
    )

    blf_file.parent.mkdir(parents=True)
    dbc_file.parent.mkdir(parents=True)
    blf_file.write_bytes(b"")
    dbc_file.write_bytes(b"")

    FakeChargingAnalysisService.calls.clear()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        main_module,
        "ChargingAnalysisService",
        FakeChargingAnalysisService,
    )

    return blf_file, dbc_file


def test_main_runs_charging_analysis(tmp_path, monkeypatch, capsys) -> None:
    blf_file, dbc_file = configure_main(monkeypatch, tmp_path)

    result = main_module.main()
    captured = capsys.readouterr()

    assert result is None
    assert len(FakeChargingAnalysisService.calls) == 1
    assert FakeChargingAnalysisService.calls[0]["blf_file"] == Path(
        r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
    )
    assert FakeChargingAnalysisService.calls[0]["dbc_file"] == Path(
        r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
    )
    assert blf_file.exists()
    assert dbc_file.exists()
    assert "EV TRACE PROCESSOR" in captured.out
    assert "PROCESSING COMPLETE" in captured.out


def test_main_reports_analysis_results(tmp_path, monkeypatch, capsys) -> None:
    configure_main(monkeypatch, tmp_path)

    main_module.main()
    captured = capsys.readouterr()

    assert "ANALYSIS RESULTS" in captured.out
    assert "Decoded Messages: 3121" in captured.out
    assert "Timeline Entries: 6" in captured.out
    assert "Events Detected: 6" in captured.out


def test_main_reports_findings(tmp_path, monkeypatch, capsys) -> None:
    configure_main(monkeypatch, tmp_path)

    main_module.main()
    captured = capsys.readouterr()

    assert "ROOT CAUSE FINDINGS" in captured.out
    assert "- Charging permission denied." in captured.out


def test_main_reports_generated_reports(tmp_path, monkeypatch, capsys) -> None:
    configure_main(monkeypatch, tmp_path)

    main_module.main()
    captured = capsys.readouterr()

    assert "GENERATED REPORTS" in captured.out
    assert "Event Report: reports\\charging\\charging_event_report.txt" in captured.out
    assert "Event Summary: reports\\charging\\charging_event_summary.txt" in captured.out
    assert "Diagnostic Report: CHARGING DIAGNOSTIC REPORT" in captured.out
    assert "Case Summary: reports\\charging\\charging_case_summary.txt" in captured.out


def test_main_reports_missing_blf(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)

    result = main_module.main()
    captured = capsys.readouterr()

    assert result is None
    assert (
        "BLF file not found: "
        "data\\blf\\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
        in captured.out
    )


def test_main_reports_missing_dbc(tmp_path, monkeypatch, capsys) -> None:
    blf_file = (
        tmp_path
        / "data"
        / "blf"
        / "VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
    )
    blf_file.parent.mkdir(parents=True)
    blf_file.write_bytes(b"")
    monkeypatch.chdir(tmp_path)

    result = main_module.main()
    captured = capsys.readouterr()

    assert result is None
    assert (
        "DBC file not found: "
        "dbc\\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
        in captured.out
    )
