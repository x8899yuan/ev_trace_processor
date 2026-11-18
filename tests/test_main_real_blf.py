import argparse
from pathlib import Path

import pytest

import main as main_module


REPORTS_DIR = Path("reports")


def _discover_blf_file() -> Path:
    directory = Path("data") / "blf"
    files = sorted(path for path in directory.iterdir() if path.is_file() and path.suffix.lower() == ".blf") if directory.exists() else []
    if not files:
        pytest.skip(f"No BLF real-trace fixture found under {directory}")
    return files[0]


def _latest_session_pair() -> tuple[Path, Path]:
    summaries = sorted(REPORTS_DIR.glob("session_summary_??????????????.txt"), key=lambda path: path.stat().st_mtime_ns)
    assert summaries, "No timestamped session summary was generated"
    summary = summaries[-1]
    html = summary.with_suffix(".html")
    return summary, html


def test_main_real_session(monkeypatch) -> None:
    _discover_blf_file()
    monkeypatch.setattr(main_module, "parse_args", lambda: argparse.Namespace(no_open=True))
    result = main_module.main()
    assert result == 0

    summary_file, html_file = _latest_session_pair()
    assert summary_file.exists()
    assert html_file.exists()
    run_id = summary_file.stem.removeprefix("session_summary_")
    assert len(run_id) == 14 and run_id.isdigit()
    assert html_file.name == f"session_summary_{run_id}.html"

    summary = summary_file.read_text(encoding="utf-8")
    html = html_file.read_text(encoding="utf-8")
    assert "Vehicle Test Session Engineering Summary" in summary
    assert "BLF: ANALYZED" in summary
    assert "Vehicle Test Session Engineering Summary" in html
