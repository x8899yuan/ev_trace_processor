import argparse
from pathlib import Path

import main as main_module


PROCESS_RESULT = {
    "processed_trace_types": ["blf", "pcap"],
    "vehicle_identity": {
        "vin": "1V2ZZZE81TC000011",
        "source": "BLF / VIN_01",
    },
    "summary_path": Path("reports/test_session_summary.txt"),
    "html_path": Path("reports/test_session_summary.html"),
}


class FakeSessionProcessorService:
    calls = []
    result = PROCESS_RESULT
    error = None

    def __init__(self, handlers):
        self.handlers = handlers

    def process(self, discovered):
        self.__class__.calls.append(discovered)
        if self.__class__.error is not None:
            raise self.__class__.error
        return self.__class__.result


class FakeSessionTraceHandlers:
    def build(self):
        return {"fake": object()}


def configure_main(monkeypatch, tmp_path, *, no_open=True):
    blf_file = tmp_path / "data" / "blf" / "vehicle.blf"
    pcap_file = tmp_path / "data" / "pcap" / "capture.pcap"
    ignored_file = tmp_path / "data" / "pcap" / "notes.txt"
    blf_file.parent.mkdir(parents=True)
    pcap_file.parent.mkdir(parents=True)
    blf_file.write_bytes(b"")
    pcap_file.write_bytes(b"")
    ignored_file.write_text("ignore", encoding="utf-8")

    FakeSessionProcessorService.calls.clear()
    FakeSessionProcessorService.result = PROCESS_RESULT
    FakeSessionProcessorService.error = None
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "SessionProcessorService", FakeSessionProcessorService)
    monkeypatch.setattr(main_module, "SessionTraceHandlers", FakeSessionTraceHandlers)
    monkeypatch.setattr(
        main_module,
        "parse_args",
        lambda: argparse.Namespace(no_open=no_open),
    )
    return blf_file, pcap_file


def test_discover_traces_returns_supported_files(tmp_path, monkeypatch) -> None:
    blf_file, pcap_file = configure_main(monkeypatch, tmp_path)

    discovered = main_module.discover_traces()

    assert discovered["blf"] == [Path("data/blf/vehicle.blf")]
    assert discovered["pcap"] == [Path("data/pcap/capture.pcap")]
    assert discovered["dlt"] == []
    assert discovered["mf4"] == []
    assert blf_file.exists()
    assert pcap_file.exists()


def test_main_processes_discovered_traces(tmp_path, monkeypatch, capsys) -> None:
    configure_main(monkeypatch, tmp_path)

    result = main_module.main()
    captured = capsys.readouterr()

    assert result == 0
    assert len(FakeSessionProcessorService.calls) == 1
    discovered = FakeSessionProcessorService.calls[0]
    assert discovered["blf"] == [Path("data/blf/vehicle.blf")]
    assert discovered["pcap"] == [Path("data/pcap/capture.pcap")]
    assert "EV TRACE PROCESSOR" in captured.out
    assert "PROCESSING COMPLETE" in captured.out
    assert "Processed trace types: BLF, PCAP" in captured.out
    assert "VIN: 1V2ZZZE81TC000011" in captured.out
    assert "VIN evidence: BLF / VIN_01" in captured.out
    assert "Session TXT:  reports\\test_session_summary.txt" in captured.out
    assert "Session HTML: reports\\test_session_summary.html" in captured.out


def test_main_no_open_does_not_launch_browser(tmp_path, monkeypatch) -> None:
    configure_main(monkeypatch, tmp_path, no_open=True)
    opened = []
    monkeypatch.setattr(main_module.webbrowser, "open", opened.append)

    assert main_module.main() == 0
    assert opened == []


def test_main_opens_session_html_by_default(tmp_path, monkeypatch, capsys) -> None:
    configure_main(monkeypatch, tmp_path, no_open=False)
    opened = []
    monkeypatch.setattr(main_module.webbrowser, "open", opened.append)

    assert main_module.main() == 0
    captured = capsys.readouterr()

    assert len(opened) == 1
    assert opened[0].startswith("file:")
    assert opened[0].endswith("/reports/test_session_summary.html")
    assert "Opened session HTML in the default browser." in captured.out


def test_main_reports_no_supported_traces(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        main_module,
        "parse_args",
        lambda: argparse.Namespace(no_open=True),
    )

    result = main_module.main()
    captured = capsys.readouterr()

    assert result == 2
    assert "No supported traces were provided." in captured.out
    assert "Place at least one BLF, DLT, PCAP, or MF4 trace" in captured.out


def test_main_reports_processing_failure(tmp_path, monkeypatch, capsys) -> None:
    configure_main(monkeypatch, tmp_path)
    FakeSessionProcessorService.error = RuntimeError("synthetic failure")

    result = main_module.main()
    captured = capsys.readouterr()

    assert result == 1
    assert "PROCESSING FAILED" in captured.out
    assert "RuntimeError: synthetic failure" in captured.out
