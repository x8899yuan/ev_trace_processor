from pathlib import Path

from services.session_report_manifest import TestSessionReportManifest


def test_manifest_exposes_only_curated_pcap_links(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    din = root / "pcap" / "din70121"
    tls = root / "pcap" / "iso15118"
    din.mkdir(parents=True)
    tls.mkdir(parents=True)
    (din / "index.html").write_text("din", encoding="utf-8")
    (tls / "index.html").write_text("tls", encoding="utf-8")
    (din / "capture").mkdir()
    (din / "capture" / "a.html").write_text("a", encoding="utf-8")

    pcap = TestSessionReportManifest().build(root)["traces"]["PCAP"]

    assert "groups" not in pcap
    assert [item["title"] for item in pcap["reports"]] == [
        "DIN 70121 Detailed Reports",
        "ISO 15118 / TLS Detailed Reports",
    ]
    assert all(item["html_exists"] for item in pcap["reports"])
