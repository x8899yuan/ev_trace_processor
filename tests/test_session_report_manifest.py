from pathlib import Path

from services.session_report_manifest import TestSessionReportManifest


def _write_pair(root: Path, relative_txt: str) -> None:
    txt = root / relative_txt
    txt.parent.mkdir(parents=True, exist_ok=True)
    txt.write_text("report\n", encoding="utf-8")
    txt.with_suffix(".html").write_text("<html></html>\n", encoding="utf-8")


def test_test_session_report_manifest_current_artifacts(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    for relative in (
        "blf/blf_analysis_report.txt",
        "blf/blf_case_summary.txt",
        "blf/blf_inventory.txt",
        "blf/blf_statistics.txt",
        "dlt/dlt_analysis_report.txt",
        "dlt/dlt_case_summary.txt",
        "dlt/dlt_inventory.txt",
        "dlt/dlt_statistics.txt",
        "mf4/mf4_analysis_report.txt",
        "mf4/mf4_case_summary.txt",
    ):
        _write_pair(root, relative)

    (root / "pcap" / "din70121").mkdir(parents=True)
    (root / "pcap" / "iso15118").mkdir(parents=True)
    (root / "pcap" / "din70121" / "index.html").write_text("<html></html>\n", encoding="utf-8")
    (root / "pcap" / "iso15118" / "index.html").write_text("<html></html>\n", encoding="utf-8")

    manifest = TestSessionReportManifest().build(root)

    assert manifest["session"] == {
        "title": "Vehicle Test Session Engineering Summary",
        "txt": "test_session_summary.txt",
        "html": "test_session_summary.html",
    }

    traces = manifest["traces"]
    assert set(traces) == {"BLF", "DLT", "PCAP", "MF4"}
    assert [item["title"] for item in traces["BLF"]["reports"]] == [
        "Analysis Report",
        "Case Summary",
        "Blf Inventory",
        "Blf Statistics",
    ]
    assert [item["title"] for item in traces["DLT"]["reports"]] == [
        "Analysis Report",
        "Case Summary",
        "Inventory",
        "Statistics",
    ]
    assert [item["title"] for item in traces["MF4"]["reports"]] == [
        "Analysis Report",
        "Case Summary",
    ]
    assert [item["title"] for item in traces["PCAP"]["reports"]] == [
        "DIN 70121 Detailed Reports",
        "ISO 15118 / TLS Detailed Reports",
    ]
    assert all(item["txt_exists"] for item in traces["BLF"]["reports"])
    assert all(item["txt_exists"] for item in traces["DLT"]["reports"])
    assert all(item["txt_exists"] for item in traces["MF4"]["reports"])
    assert all(item["html_exists"] for item in traces["PCAP"]["reports"])


def test_manifest_tracks_html_availability_without_requiring_html(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    txt = root / "blf" / "blf_case_summary.txt"
    txt.parent.mkdir(parents=True)
    txt.write_text("summary\n", encoding="utf-8")

    manifest = TestSessionReportManifest().build(root)
    entries = []
    for trace_name in ("BLF", "DLT", "PCAP", "MF4"):
        entries.extend(manifest["traces"][trace_name]["reports"])

    assert entries
    for item in entries:
        assert isinstance(item["txt_exists"], bool)
        assert isinstance(item["html_exists"], bool)
