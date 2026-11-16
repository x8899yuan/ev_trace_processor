from services.session_evidence_adapter import TestSessionEvidenceAdapter
from services.session_summary_service import TestSessionSummaryService


def test_pcap_summary_exposes_engineering_assessment_not_availability_or_filenames() -> None:
    pcap = TestSessionEvidenceAdapter().adapt_pcap(
        {
            "capture": {"file_name": "multiple PCAP captures", "file_path": "multiple PCAP captures", "packet_count": 100},
            "protocol_counts": {"HOMEPLUG_AV": 80, "TCP": 20},
        },
        din70121={"selected_protocol": "DIN 70121", "furthest_message": "CurrentDemand", "session_completion": "NOT_OBSERVED"},
        iso15118_tls={"tls_version": "TLS 1.2", "server_certificate_observed": True, "client_certificate_observed": False},
    )

    text = TestSessionSummaryService().generate_summary(pcap=pcap)

    assert "Network communication: OBSERVED" in text
    assert "Dominant observed protocol: HOMEPLUG_AV" in text
    assert "DIN 70121: OBSERVED" in text
    assert "DIN 70121 negotiated protocol: DIN 70121" in text
    assert "DIN 70121 progression: CurrentDemand" in text
    assert "DIN 70121 session completion: NOT_OBSERVED" in text
    assert "ISO 15118 / TLS: OBSERVED" in text
    assert "TLS version: TLS 1.2" in text
    assert "TLS server certificate: OBSERVED" in text
    assert "TLS client-certificate authentication: NOT_OBSERVED" in text
    assert "structured analysis: AVAILABLE" not in text
    assert "source captures:" not in text
