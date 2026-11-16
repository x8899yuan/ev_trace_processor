from pathlib import Path

import pytest

from services.iso15118_tls_report_service import Iso15118TlsReportService


PCAP = Path(r"data\pcap\2025_09_25_VWID4IDS54_PnC_ToggleOff_001.pcap")
EXPECTED_NAMES = {
    "analysis_report": "iso15118_tls_analysis_report.txt",
    "certificate_inventory": "iso15118_tls_certificate_inventory.txt",
    "statistics": "iso15118_tls_statistics.txt",
    "case_summary": "iso15118_tls_case_summary.txt",
}


@pytest.fixture(scope="module")
def generated_reports(tmp_path_factory):
    if not PCAP.exists():
        pytest.skip(f"real PCAP not available: {PCAP}")
    output_dir = tmp_path_factory.mktemp("iso15118_tls_reports")
    reports = Iso15118TlsReportService().generate(PCAP, output_dir)
    return output_dir, reports


def read_report(reports, key):
    return reports[key].read_text(encoding="utf-8")


def test_generate_missing_pcap_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        Iso15118TlsReportService().generate(
            r"data\pcap\missing_iso15118_tls_capture.pcap",
            tmp_path,
        )


def test_generate_creates_four_standard_text_reports(generated_reports):
    output_dir, reports = generated_reports
    assert set(reports) == set(EXPECTED_NAMES)
    for key, filename in EXPECTED_NAMES.items():
        assert reports[key] == output_dir / filename
        assert reports[key].is_file()
        assert reports[key].stat().st_size > 0


def test_analysis_report_contains_validated_tls_session(generated_reports):
    _, reports = generated_reports
    text = read_report(reports, "analysis_report").lower()
    assert "tls version: tls 1.2" in text
    assert "first tls packet: 477" in text
    assert "last tls packet: 2511" in text
    assert "first encrypted application-data packet: 501" in text
    assert "client: fe80::4a31:33ff:fe00:1b9:49153" in text
    assert "server: fe80::161f:baff:fe10:ec20:56320" in text
    assert "selected cipher suite: 0xc023" in text


def test_analysis_report_contains_handshake_anchors(generated_reports):
    _, reports = generated_reports
    text = read_report(reports, "analysis_report").lower()
    for expected in (
        "packet 477: clienthello",
        "packet 479: serverhello",
        "packet 480: certificate",
        "packet 485: serverkeyexchange",
        "packet 487: serverhellodone",
        "packet 492: clientkeyexchange",
    ):
        assert expected in text


def test_certificate_inventory_contains_three_validated_certificates(generated_reports):
    _, reports = generated_reports
    text = read_report(reports, "certificate_inventory").lower()
    assert "certificates recovered: 3" in text
    assert "033ecaf6caa5fa0cc412921c99db1ce4245e0861a997e12af4cec32ac5f19d5e" in text
    assert "8595da233dd888c9e9a4876a2691834b47bc2aa31405df18abce1a0e1718bcfa" in text
    assert "986bb0e4c8b76694a3cad385834d13bf565ad963472fadafab82778e3b28abe6" in text
    assert "cn=usgr1e000001060" in text
    assert "o=electrifyamerica" in text
    assert "cn=us cpo sub2 ca g2.2.2" in text
    assert "cn=us cpo sub1 ca g2.2" in text
    assert "cn=us v2g rootca g2" in text


def test_certificate_inventory_documents_chain_relationships(generated_reports):
    _, reports = generated_reports
    text = read_report(reports, "certificate_inventory").lower()
    assert "certificate 1 -> certificate 2" in text
    assert "certificate 2 -> certificate 3" in text
    assert text.count("issuer_subject_match=true") == 2
    assert text.count("authority_subject_key_id_match=true") == 2


def test_statistics_report_contains_validated_counts(generated_reports):
    _, reports = generated_reports
    text = read_report(reports, "statistics").lower()
    assert "server certificates recovered: 3" in text
    assert "leaf certificates: 1" in text
    assert "ca certificates: 2" in text
    assert "validated transmitted chain links: 2/2" in text
    assert "tls certificaterequest seen: false" in text
    assert "tls client certificate seen: false" in text


def test_reports_preserve_encrypted_application_evidence_boundary(generated_reports):
    _, reports = generated_reports
    analysis = read_report(reports, "analysis_report").lower()
    summary = read_report(reports, "case_summary").lower()
    statistics = read_report(reports, "statistics").lower()
    for text in (analysis, statistics):
        assert "decryption keys available: false" in text
        assert "iso 15118 application decoding available: false" in text
    assert "encrypted iso 15118 application messages are not inferred" in analysis
    assert "no tls session keys were found with the capture" in summary
    assert "iso 15118 application messages readable: indeterminate" in summary
    assert "paymentdetails observed: indeterminate" in summary
    assert "contract certificate exchanged: indeterminate" in summary
    assert "pnc authorization completed: indeterminate" in summary
    assert "pnc status: indeterminate from available evidence" in summary


def test_reports_do_not_mislabel_tls_chain_as_contract_certificate(generated_reports):
    _, reports = generated_reports
    inventory = read_report(reports, "certificate_inventory").lower()
    summary = read_report(reports, "case_summary").lower()
    assert "not an iso 15118 contract-certificate inventory" in inventory
    assert "the recovered tls server chain is separate from an iso 15118 vehicle contract-certificate chain" in summary


def test_case_summary_keeps_capture_independent_from_blf_dlt_vehicle(generated_reports):
    _, reports = generated_reports
    text = read_report(reports, "case_summary").lower()
    assert "independent vehicle/test source" in text
    assert "no relationship to the project's blf, dlt, or other same-vehicle traces is assumed" in text


def test_reports_do_not_expose_private_keys_or_full_certificates(generated_reports):
    _, reports = generated_reports
    inventory = read_report(reports, "certificate_inventory").lower()
    assert "no private keys or full certificate contents are included" in inventory
    assert "-----begin certificate-----" not in inventory
    assert "private key" not in inventory.replace("no private keys", "")
