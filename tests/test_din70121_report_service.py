from pathlib import Path

import pytest

from services.din70121_exi_grammar import DIN_NAMESPACE
from services.din70121_report_service import Din70121ReportService


PCAP = Path("data/pcap/20250401122302-700006-18-G3-PWR-LOSS-OLD-SOFT-msduEx.pcap")


@pytest.fixture(scope="module")
def real_pcap():
    if not PCAP.is_file():
        pytest.skip(f"Real MSDU PCAP not available: {PCAP}")
    return PCAP


@pytest.fixture
def report_service(tmp_path):
    return Din70121ReportService(output_dir=tmp_path)


def test_generate_creates_markdown_report(report_service, real_pcap, tmp_path):
    output = report_service.generate(real_pcap)
    assert output == tmp_path / f"{real_pcap.stem}_din70121_report.md"
    assert output.is_file()
    assert output.stat().st_size > 0


def test_generate_report_alias_creates_report(report_service, real_pcap):
    output = report_service.generate_report(real_pcap)
    assert output.is_file()
    assert output.suffix == ".md"


def test_report_contains_capture_summary(report_service, real_pcap):
    output = report_service.generate(real_pcap)
    text = output.read_text(encoding="utf-8")
    assert "# DIN 70121 PCAP Analysis Report" in text
    assert str(real_pcap) in text
    assert "PCAP link type: `160`" in text
    assert "Total PCAP packets: `1967`" in text
    assert "V2GTP EXI frames: `853`" in text
    assert f"Negotiated application namespace: `{DIN_NAMESPACE}`" in text
    assert "DIN 70121 selected: `yes`" in text


def test_report_contains_all_validated_message_anchors(report_service, real_pcap):
    output = report_service.generate(real_pcap)
    text = output.read_text(encoding="utf-8")
    expected = {
        "SupportedAppProtocolReq": 93,
        "SupportedAppProtocolRes": 95,
        "SessionSetupReq": 98,
        "SessionSetupRes": 100,
        "ServiceDiscoveryReq": 103,
        "ServiceDiscoveryRes": 105,
        "ServicePaymentSelectionReq": 108,
        "ServicePaymentSelectionRes": 110,
        "ContractAuthenticationReq": 113,
        "ContractAuthenticationRes": 115,
        "ChargeParameterDiscoveryReq": 156,
        "ChargeParameterDiscoveryRes": 158,
        "CableCheckReq": 224,
        "CableCheckRes": 228,
        "PreChargeReq": 909,
        "PreChargeRes": 911,
        "PowerDeliveryReq": 1027,
        "PowerDeliveryRes": 1029,
        "CurrentDemandReq": 1032,
        "CurrentDemandRes": 1034,
    }
    for message_name, packet_number in expected.items():
        assert f"| {message_name} | {packet_number} |" in text


def test_report_contains_observed_session_sequence(report_service, real_pcap):
    output = report_service.generate(real_pcap)
    text = output.read_text(encoding="utf-8")
    assert "SupportedAppProtocol -> SessionSetup -> ServiceDiscovery" in text
    assert "ContractAuthentication -> ChargeParameterDiscovery -> CableCheck" in text
    assert "PreCharge -> PowerDelivery -> CurrentDemand" in text


def test_report_describes_state_transitions_and_loops(report_service, real_pcap):
    output = report_service.generate(real_pcap)
    text = output.read_text(encoding="utf-8").lower()
    assert "packet 153" in text
    assert "packet 220" in text
    assert "cablecheck forms a long repeated exchange" in text
    assert "precharge forms a variable control loop" in text
    assert "currentdemand continues as a long variable charging loop" in text


def test_report_records_abrupt_current_demand_termination(report_service, real_pcap):
    output = report_service.generate(real_pcap)
    text = output.read_text(encoding="utf-8").lower()
    assert "last v2g exi packet: `1867`" in text
    assert "last exi payload length: `41` bytes" in text
    assert "currentdemand-like" in text
    assert "no following exi response" in text
    assert "powerdelivery stop: **not observed**" in text
    assert "weldingdetectionreq/res: **not observed**" in text
    assert "sessionstopreq/res: **not observed**" in text
    assert "ends during the currentdemand charging loop" in text


def test_report_documents_confidence_and_pnc_boundary(report_service, real_pcap):
    output = report_service.generate(real_pcap)
    text = output.read_text(encoding="utf-8").lower()
    assert "captured-vector" in text
    assert "sequence-correlated-captured-vector" in text
    assert "xsd-derived exi field decoding remains pending" in text
    assert "not interpreted as iso 15118 plug & charge" in text
    assert "private keys" in text


def test_generate_missing_pcap_raises(report_service, tmp_path):
    missing = tmp_path / "missing.pcap"
    with pytest.raises(FileNotFoundError):
        report_service.generate(missing)



def test_generate_creates_four_standard_text_reports(report_service, real_pcap, tmp_path):
    report_service.generate(real_pcap)
    expected = [
        "din70121_analysis_report.txt",
        "din70121_case_summary.txt",
        "din70121_inventory.txt",
        "din70121_statistics.txt",
    ]
    for name in expected:
        path = tmp_path / name
        assert path.is_file()
        assert path.stat().st_size > 0


def test_standard_reports_contain_expected_content(report_service, real_pcap, tmp_path):
    report_service.generate(real_pcap)
    analysis = (tmp_path / "din70121_analysis_report.txt").read_text(encoding="utf-8").lower()
    summary = (tmp_path / "din70121_case_summary.txt").read_text(encoding="utf-8").lower()
    inventory = (tmp_path / "din70121_inventory.txt").read_text(encoding="utf-8").lower()
    statistics = (tmp_path / "din70121_statistics.txt").read_text(encoding="utf-8").lower()
    assert "currentdemand" in analysis and "1867" in analysis
    assert "powerdelivery stop: not observed" in summary
    assert "weldingdetection: not observed" in summary
    assert "sessionstop: not observed" in summary
    assert "sessionsetupreq" in inventory
    assert "currentdemandres" in inventory
    assert "weldingdetectionreq" in inventory
    assert "sessionstopres" in inventory
    assert "total pcap packets: 1967" in statistics
    assert "total v2gtp exi frames: 853" in statistics
    assert "packet 153" in statistics
    assert "packet 220" in statistics
    assert "packet 1867" in statistics


def test_standard_reports_and_markdown_share_termination_conclusion(report_service, real_pcap, tmp_path):
    markdown_output = report_service.generate(real_pcap)
    markdown = markdown_output.read_text(encoding="utf-8").lower()
    analysis = (tmp_path / "din70121_analysis_report.txt").read_text(encoding="utf-8").lower()
    summary = (tmp_path / "din70121_case_summary.txt").read_text(encoding="utf-8").lower()
    for phrase in ("1867", "powerdelivery stop", "weldingdetection", "sessionstop", "not observed"):
        assert phrase in markdown
        assert phrase in analysis
        assert phrase in summary
