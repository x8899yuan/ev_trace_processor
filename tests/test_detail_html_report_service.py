from pathlib import Path

from services.detail_html_report_service import DetailHtmlReportService
from services.session_report_manifest import TestSessionReportManifest


def test_detail_html_generation_and_manifest_links(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    blf = root / "blf"
    din = root / "pcap" / "din70121" / "capture"
    blf.mkdir(parents=True)
    din.mkdir(parents=True)
    (blf / "blf_case_summary.txt").write_text(
        "BLF CASE SUMMARY\nCharging not observed\n",
        encoding="utf-8",
    )
    (din / "din70121_case_summary.txt").write_text(
        "DIN 70121 CASE SUMMARY\nCurrentDemand\n",
        encoding="utf-8",
    )

    outputs = DetailHtmlReportService().generate_all(root)
    assert blf / "blf_case_summary.html" in outputs
    assert din / "din70121_case_summary.html" in outputs

    blf_html = (blf / "blf_case_summary.html").read_text(encoding="utf-8")
    din_html = (din / "din70121_case_summary.html").read_text(encoding="utf-8")
    assert 'href="../test_session_summary.html"' in blf_html
    assert 'href="../../../test_session_summary.html"' in din_html
    assert "Charging not observed" in blf_html
    assert "CurrentDemand" in din_html

    manifest = TestSessionReportManifest().build(root)
    blf_entries = manifest["traces"]["BLF"]["reports"]
    pcap_entries = manifest["traces"]["PCAP"]["reports"]
    assert any(
        item["html_exists"] and item["html"] == "blf/blf_case_summary.html"
        for item in blf_entries
    )
    assert any(
        item["title"] == "DIN 70121 Detailed Reports"
        and item["html"] == "pcap/din70121/index.html"
        for item in pcap_entries
    )
