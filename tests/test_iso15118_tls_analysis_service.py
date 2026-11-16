from pathlib import Path

import pytest

from services.iso15118_tls_analysis_service import Iso15118TlsAnalysisService


PCAP = Path(r"data\pcap\2025_09_25_VWID4IDS54_PnC_ToggleOff_001.pcap")


@pytest.fixture(scope="module")
def analysis():
    if not PCAP.exists():
        pytest.skip(f"real PCAP not available: {PCAP}")
    return Iso15118TlsAnalysisService().analyze(PCAP)


def test_missing_pcap_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        Iso15118TlsAnalysisService().analyze(r"data\pcap\missing_iso15118_tls_capture.pcap")


def test_detects_tls_session_and_boundaries(analysis):
    assert analysis["tls_detected"] is True
    assert analysis["first_tls_packet"] == 477
    assert analysis["last_tls_packet"] == 2511
    assert analysis["first_application_data_packet"] == 501
    assert analysis["application_encrypted"] is True


def test_identifies_tls_endpoints(analysis):
    assert analysis["client"] == {"ip": "fe80::4a31:33ff:fe00:1b9", "port": 49153}
    assert analysis["server"] == {"ip": "fe80::161f:baff:fe10:ec20", "port": 56320}


def test_identifies_tls_version_and_cipher_suite(analysis):
    assert analysis["tls_version"].lower() == "tls 1.2"
    assert [value.lower() for value in analysis["offered_cipher_suites"]] == ["0xc023"]
    assert analysis["selected_cipher_suite"].lower() == "0xc023"


def test_reports_validated_handshake_anchors(analysis):
    anchors = {(item["packet"], item["name"].lower()) for item in analysis["handshake_anchors"]}
    expected = {
        (477, "clienthello"),
        (479, "serverhello"),
        (480, "certificate"),
        (485, "serverkeyexchange"),
        (487, "serverhellodone"),
        (492, "clientkeyexchange"),
    }
    assert expected.issubset(anchors)


def test_does_not_report_tls_client_certificate(analysis):
    assert analysis["certificate_request_seen"] is False
    assert analysis["tls_client_certificate_seen"] is False


def test_extracts_three_server_certificates(analysis):
    certificates = analysis["server_certificates"]
    assert len(certificates) == 3
    assert [item["packet"] for item in certificates] == [480, 480, 480]
    assert [item["der_length"] for item in certificates] == [600, 554, 571]
    assert [item["sha256"].lower() for item in certificates] == [
        "033ecaf6caa5fa0cc412921c99db1ce4245e0861a997e12af4cec32ac5f19d5e",
        "8595da233dd888c9e9a4876a2691834b47bc2aa31405df18abce1a0e1718bcfa",
        "986bb0e4c8b76694a3cad385834d13bf565ad963472fadafab82778e3b28abe6",
    ]


def test_leaf_certificate_metadata(analysis):
    leaf = analysis["server_certificates"][0]
    subject = leaf["subject"].lower()
    issuer = leaf["issuer"].lower()
    assert "cn=usgr1e000001060" in subject
    assert "o=electrifyamerica" in subject
    assert "dc=cpo" in subject
    assert "cn=us cpo sub2 ca g2.2.2" in issuer
    assert leaf["is_ca"] is False
    assert leaf["public_key"]["algorithm"].lower() == "ec"
    assert leaf["public_key"]["curve"].lower() == "secp256r1"
    assert leaf["public_key"]["key_size"] == 256
    assert leaf["signature_algorithm"].lower() == "ecdsa-with-sha256"
    assert {value.lower() for value in leaf["key_usage"]} == {"digital_signature", "key_agreement"}


def test_ca_certificate_metadata(analysis):
    sub2, sub1 = analysis["server_certificates"][1:]
    assert sub2["is_ca"] is True
    assert sub2["path_length"] == 0
    assert "cn=us cpo sub2 ca g2.2.2" in sub2["subject"].lower()
    assert "cn=us cpo sub1 ca g2.2" in sub2["issuer"].lower()
    assert sub1["is_ca"] is True
    assert sub1["path_length"] == 1
    assert "cn=us cpo sub1 ca g2.2" in sub1["subject"].lower()
    assert "cn=us v2g rootca g2" in sub1["issuer"].lower()
    assert "dc=v2g" in sub1["subject"].lower()
    for certificate in (sub2, sub1):
        assert {value.lower() for value in certificate["key_usage"]} == {"key_cert_sign", "crl_sign"}


def test_certificate_chain_relationships(analysis):
    relationships = analysis["certificate_chain_relationships"]
    assert relationships == [
        {
            "child_index": 1,
            "issuer_index": 2,
            "issuer_subject_match": True,
            "authority_subject_key_id_match": True,
        },
        {
            "child_index": 2,
            "issuer_index": 3,
            "issuer_subject_match": True,
            "authority_subject_key_id_match": True,
        },
    ]


def test_application_visibility_is_conservative_without_keys(analysis):
    assert analysis["application_encrypted"] is True
    assert analysis["decryption_keys_available"] is False
    assert analysis["iso15118_application_decoding_available"] is False
