from pathlib import Path

from services.session_trace_handlers import SessionTraceHandlers


def test_din70121_mapping_extracts_progression_and_completion(tmp_path: Path) -> None:
    directory = tmp_path / "din"
    directory.mkdir()
    report = directory / "din70121_case_summary.txt"
    report.write_text(
        "DIN 70121\nSessionSetup\nServiceDiscovery\nPowerDelivery\nCurrentDemand\n",
        encoding="utf-8",
    )

    result = SessionTraceHandlers()._din70121_session_result(
        [{"source_file": "capture.pcap", "report": str(report)}]
    )

    assert result["analysis_status"] == "OBSERVED"
    assert result["selected_protocol"] == "DIN 70121"
    assert result["furthest_message"] == "CurrentDemand"
    assert result["session_completion"] == "NOT_OBSERVED"


def test_tls_mapping_extracts_version_and_certificate_observations() -> None:
    analyses = [
        {
            "source_file": "capture.pcap",
            "analysis": {
                "tls_version": "TLS 1.2",
                "server_certificates": [{"sha256": "abc"}],
                "client_certificate_observed": False,
            },
        }
    ]

    result = SessionTraceHandlers()._tls_session_result(analyses, [])

    assert result["analysis_status"] == "OBSERVED"
    assert result["tls_version"] == "TLS 1.2"
    assert result["server_certificate_observed"] is True
    assert result["client_certificate_observed"] is False


def test_mapping_reports_not_observed_without_positive_evidence(tmp_path: Path) -> None:
    report = tmp_path / "empty.txt"
    report.write_text("No decoded V2G messages", encoding="utf-8")

    din = SessionTraceHandlers()._din70121_session_result(
        [{"source_file": "capture.pcap", "report": str(report)}]
    )
    tls = SessionTraceHandlers()._tls_session_result(
        [{"source_file": "capture.pcap", "analysis": {}}],
        [],
    )

    assert din["analysis_status"] == "NOT_OBSERVED"
    assert tls["analysis_status"] == "NOT_OBSERVED"
