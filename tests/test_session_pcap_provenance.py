from services.session_evidence_adapter import TestSessionEvidenceAdapter


def test_pcap_session_evidence_keeps_specialized_capture_provenance() -> None:
    analysis = {
        "capture": {
            "file_name": "5 PCAP captures",
            "file_path": "multiple PCAP captures",
            "packet_count": 123,
        },
        "protocol_counts": {"HOMEPLUG_AV": 100, "TCP": 23},
    }
    din70121 = {
        "capture_count": 2,
        "captures": [
            {"source_file": r"data\pcap\a-msdu.pcap", "report": "a"},
            {"source_file": r"data\pcap\b-msduEx.pcap", "report": "b"},
        ],
    }
    tls = {
        "capture_count": 1,
        "captures": [
            {"source_file": r"data\pcap\pnc.pcap", "analysis": {"tls_version": "TLS 1.2"}},
        ],
    }

    result = TestSessionEvidenceAdapter().adapt_pcap(
        analysis,
        din70121=din70121,
        iso15118_tls=tls,
    )

    assert result is not None
    assert result["source_file"] == "multiple PCAP captures"
    assert result["protocol_counts"] == {"HOMEPLUG_AV": 100, "TCP": 23}
    assert result["network_assessment"]["status"] == "OBSERVED"
    assert result["network_assessment"]["dominant_protocol"] == "HOMEPLUG_AV"
    assert result["din70121"] == din70121
    assert result["din70121_assessment"]["captures_analyzed"] == 2
    assert result["iso15118_tls"] == tls
    assert result["iso15118_tls_assessment"]["captures_analyzed"] == 1


def test_pcap_provenance_does_not_invent_sources_for_legacy_evidence() -> None:
    result = TestSessionEvidenceAdapter().adapt_pcap(
        {"capture": {"file_name": "single.pcap", "packet_count": 1}},
        din70121={"selected_protocol": "DIN 70121"},
        iso15118_tls={"tls_version": "TLS 1.2"},
    )

    assert result is not None
    assert result["source_file"] == "single.pcap"
    assert result["source_files"] == []
    assert result["din70121_assessment"] == {
        "status": "OBSERVED",
        "selected_protocol": "DIN 70121",
    }
    assert result["iso15118_tls_assessment"] == {
        "status": "OBSERVED",
        "tls_version": "TLS 1.2",
    }
