from services.session_evidence_adapter import TestSessionEvidenceAdapter
from services.session_html_report_service import TestSessionHtmlReportService as SessionHtmlReportService


def test_pcap_html_lists_all_source_files() -> None:
    pcap = TestSessionEvidenceAdapter().adapt_pcap(
        {
            "capture": {
                "file_name": "5 PCAP captures",
                "file_path": "multiple PCAP captures",
                "source_files": [
                    r"data\pcap\a.pcap",
                    r"data\pcap\b.pcap",
                    r"data\pcap\c.pcap",
                ],
                "packet_count": 10,
            },
            "protocol_counts": {"HOMEPLUG_AV": 10},
        }
    )

    html = SessionHtmlReportService().generate_report(
        {"pcap": pcap},
        {"traces": {}},
    )

    assert "Source: a.pcap, b.pcap, c.pcap" in html
    assert "Source: multiple PCAP captures" not in html
