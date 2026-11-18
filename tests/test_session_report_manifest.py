from pathlib import Path

from services.session_report_manifest import TestSessionReportManifest


RUN_ID = "20261118111230"


def _write_pair(root: Path, relative_txt: str):
    txt = root / relative_txt
    txt.parent.mkdir(parents=True, exist_ok=True)
    txt.write_text("report\n", encoding="utf-8")
    txt.with_suffix(".html").write_text("<html></html>\n", encoding="utf-8")


def test_session_report_manifest_current_run_only(tmp_path: Path):
    root = tmp_path / "reports"
    for relative in (
        f"blf/blf_analysis_report_{RUN_ID}.txt", f"blf/blf_case_summary_{RUN_ID}.txt",
        f"dlt/dlt_analysis_report_{RUN_ID}.txt", f"dlt/dlt_case_summary_{RUN_ID}.txt",
        f"mf4/mf4_analysis_report_{RUN_ID}.txt", f"mf4/mf4_case_summary_{RUN_ID}.txt",
        f"pcap/capture/pcap_analysis_report_{RUN_ID}.txt", f"pcap/capture/pcap_case_summary_{RUN_ID}.txt",
    ):
        _write_pair(root, relative)
    _write_pair(root, "blf/blf_case_summary_20261117120000.txt")

    manifest = TestSessionReportManifest().build(root, run_id=RUN_ID)
    assert manifest["session"] == {
        "title": "Vehicle Test Session Engineering Summary",
        "txt": f"session_summary_{RUN_ID}.txt",
        "html": f"session_summary_{RUN_ID}.html",
    }
    for trace in manifest["traces"].values():
        assert all(RUN_ID in item["txt"] for item in trace["reports"])
        assert all(item["txt_exists"] and item["html_exists"] for item in trace["reports"])


def test_manifest_tracks_html_availability(tmp_path: Path):
    root = tmp_path / "reports"
    txt = root / "blf" / f"blf_case_summary_{RUN_ID}.txt"
    txt.parent.mkdir(parents=True)
    txt.write_text("summary\n", encoding="utf-8")
    entries = TestSessionReportManifest().build(root, run_id=RUN_ID)["traces"]["BLF"]["reports"]
    assert len(entries) == 1
    assert entries[0]["txt_exists"] is True
    assert entries[0]["html_exists"] is False
