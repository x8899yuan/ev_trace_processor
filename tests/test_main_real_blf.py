import argparse
from pathlib import Path

import pytest

import main as main_module


BLF_FILE = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")
SUMMARY_FILE = Path(r"reports\test_session_summary.txt")
HTML_FILE = Path(r"reports\test_session_summary.html")


def test_main_real_session(monkeypatch) -> None:
    if not BLF_FILE.exists():
        pytest.skip(f"Local real-trace fixture is not available: {BLF_FILE}")

    monkeypatch.setattr(
        main_module,
        "parse_args",
        lambda: argparse.Namespace(no_open=True),
    )

    result = main_module.main()

    assert result == 0
    assert SUMMARY_FILE.exists()
    assert HTML_FILE.exists()

    summary = SUMMARY_FILE.read_text(encoding="utf-8")
    html = HTML_FILE.read_text(encoding="utf-8")

    assert "Vehicle Test Session Engineering Summary" in summary
    assert "BLF: ANALYZED" in summary
    assert "VIN: 1V2ZZZE81TC000011" in summary
    assert "Vehicle Test Session Engineering Summary" in html
