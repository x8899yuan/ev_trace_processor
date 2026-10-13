from pathlib import Path

from main import main


def test_main_without_arguments(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        ["main.py"],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert (
        "Usage: python main.py <trace_file>"
        in captured.out
    )


def test_main_processes_blf_file(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    trace_file = tmp_path / "sample.blf"
    trace_file.write_bytes(b"")

    monkeypatch.setattr(
        "sys.argv",
        ["main.py", str(trace_file)],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 0
    assert "Trace Processing Result" in captured.out
    assert "BLF" in captured.out


def test_main_processes_pcap_file(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    trace_file = tmp_path / "sample.pcap"
    trace_file.write_bytes(b"")

    monkeypatch.setattr(
        "sys.argv",
        ["main.py", str(trace_file)],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 0
    assert "PCAP" in captured.out


def test_main_processes_dlt_file(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    trace_file = tmp_path / "sample.dlt"
    trace_file.write_bytes(b"")

    monkeypatch.setattr(
        "sys.argv",
        ["main.py", str(trace_file)],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 0
    assert "DLT" in captured.out


def test_main_with_unsupported_file(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        ["main.py", "sample.xyz"],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "ERROR:" in captured.out


def test_main_reports_file_name(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    trace_file = tmp_path / "vehicle_trace.blf"
    trace_file.write_bytes(b"")

    monkeypatch.setattr(
        "sys.argv",
        ["main.py", str(trace_file)],
    )

    main()

    captured = capsys.readouterr()

    assert (
        "vehicle_trace.blf"
        in captured.out
    )


def test_main_reports_event_count(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    trace_file = tmp_path / "sample.blf"
    trace_file.write_bytes(b"")

    monkeypatch.setattr(
        "sys.argv",
        ["main.py", str(trace_file)],
    )

    main()

    captured = capsys.readouterr()

    assert "Events: 0" in captured.out