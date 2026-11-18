from pathlib import Path

from services.detail_html_report_service import DetailHtmlReportService
from services.session_report_manifest import TestSessionReportManifest


RUN_ID = "20261118111230"


def test_detail_html_generation_and_manifest_links_are_scoped_to_run_id(tmp_path: Path):
    root = tmp_path / "reports"
    blf = root / "blf"
    din = root / "pcap" / "din70121" / "capture"
    blf.mkdir(parents=True)
    din.mkdir(parents=True)
    current_blf = blf / f"blf_case_summary_{RUN_ID}.txt"
    current_din = din / f"din70121_case_summary_{RUN_ID}.txt"
    old_blf = blf / "blf_case_summary_20261117120000.txt"
    current_blf.write_text("BLF CASE SUMMARY\nCharging not observed\n", encoding="utf-8")
    current_din.write_text("DIN 70121 CASE SUMMARY\nCurrentDemand\n", encoding="utf-8")
    old_blf.write_text("OLD\n", encoding="utf-8")

    outputs = DetailHtmlReportService().generate_all(root, run_id=RUN_ID)
    assert current_blf.with_suffix(".html").resolve() in outputs
    assert current_din.with_suffix(".html").resolve() in outputs
    assert not old_blf.with_suffix(".html").exists()

    blf_html = current_blf.with_suffix(".html").read_text(encoding="utf-8")
    din_html = current_din.with_suffix(".html").read_text(encoding="utf-8")
    assert f'href="../session_summary_{RUN_ID}.html"' in blf_html
    assert f'href="../../../session_summary_{RUN_ID}.html"' in din_html

    manifest = TestSessionReportManifest().build(root, run_id=RUN_ID)
    assert any(item["html"] == f"blf/blf_case_summary_{RUN_ID}.html" for item in manifest["traces"]["BLF"]["reports"])
    assert all(RUN_ID in item["txt"] for group in manifest["traces"].values() for item in group["reports"])
