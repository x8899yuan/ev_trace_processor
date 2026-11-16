import pytest

from services.session_html_report_service import (
    TestSessionHtmlReportService as SessionHtmlReportService,
)
from services.session_summary_service import TestSessionSummaryService


BLF = {
    "source_file": r"data\blf\session.blf",
    "charging_progression": "NOT_OBSERVED",
    "connector_recognition": "NOT_RECOGNIZED",
    "control_pilot_recognition": "NOT_ESTABLISHED",
    "root_cause_status": "UNCONFIRMED",
    "fault_findings": ["BLF fault evidence"],
}
DLT = {
    "source_file": r"data\dlt\session.dlt",
    "fault_findings": ["DLT diagnostic evidence"],
    "severity_counts": {"ERROR": 1},
}
PCAP = {
    "source_file": r"data\pcap\session.pcap",
    "network_assessment": {
        "status": "OBSERVED",
        "dominant_protocol": "HOMEPLUG_AV",
    },
    "din70121_assessment": {
        "status": "OBSERVED",
        "selected_protocol": "DIN 70121",
        "furthest_message": "CurrentDemand",
        "session_completion": "NOT_OBSERVED",
    },
    "iso15118_tls_assessment": {
        "status": "OBSERVED",
        "tls_version": "TLS 1.2",
        "server_certificate_observed": True,
        "client_certificate_observed": False,
    },
}
MF4 = {
    "source_file": r"data\MF4\session.MF4",
    "charging_progression": "NOT_OBSERVED",
    "connector_recognition": "NOT_RECOGNIZED",
    "control_pilot_recognition": "NOT_ESTABLISHED",
    "cp_fault_observed": False,
    "root_cause_status": "UNCONFIRMED",
}
VEHICLE = {
    "vin": "1V2ZZZE81TC000011",
    "status": "CONFIRMED",
    "source": "BLF / VIN_01",
}
MANIFEST = {"traces": {}}


@pytest.mark.parametrize(
    "name,inputs,present,absent",
    [
        ("blf_only", {"vehicle_identity": VEHICLE, "blf": BLF}, ["BLF"], ["DLT", "PCAP / V2G", "MF4"]),
        ("dlt_only", {"dlt": DLT}, ["DLT"], ["BLF", "PCAP / V2G", "MF4"]),
        ("pcap_only", {"pcap": PCAP}, ["PCAP / V2G"], ["BLF", "DLT", "MF4"]),
        ("mf4_only", {"mf4": MF4}, ["MF4"], ["BLF", "DLT", "PCAP / V2G"]),
        ("blf_dlt", {"vehicle_identity": VEHICLE, "blf": BLF, "dlt": DLT}, ["BLF", "DLT"], ["PCAP / V2G", "MF4"]),
        ("blf_mf4", {"vehicle_identity": VEHICLE, "blf": BLF, "mf4": MF4}, ["BLF", "MF4"], ["DLT", "PCAP / V2G"]),
        ("all_four", {"vehicle_identity": VEHICLE, "blf": BLF, "dlt": DLT, "pcap": PCAP, "mf4": MF4}, ["BLF", "DLT", "PCAP / V2G", "MF4"], []),
    ],
)
def test_html_subset_matrix(name, inputs, present, absent) -> None:
    html = SessionHtmlReportService().generate_report(inputs, MANIFEST)

    assert "Vehicle Test Session Engineering Summary" in html
    assert "Input traces are treated as belonging to the same vehicle and testing session." in html

    for label in present:
        assert f"<h2>{label}</h2>" in html, f"{name}: missing {label} section"
    for label in absent:
        assert f"<h2>{label}</h2>" not in html, f"{name}: unexpected {label} section"

    if inputs.get("vehicle_identity"):
        assert "1V2ZZZE81TC000011" in html
        assert "BLF / VIN_01" in html
    else:
        assert "<h2>Vehicle Identity</h2>" not in html
        assert "VIN Evidence Source" not in html

    if inputs.get("blf") and inputs.get("mf4"):
        assert "<h2>Cross-Trace Engineering Interpretation</h2>" in html
        assert "SUPPORTED_BY_MULTIPLE_TRACES" in html
    else:
        assert "<h2>Cross-Trace Engineering Interpretation</h2>" not in html


@pytest.mark.parametrize(
    "inputs,expected,unexpected",
    [
        ({"vehicle_identity": VEHICLE, "blf": BLF}, ["BLF: ANALYZED", "VIN: 1V2ZZZE81TC000011"], ["DLT: ANALYZED", "PCAP: ANALYZED", "MF4: ANALYZED"]),
        ({"dlt": DLT}, ["DLT: ANALYZED", "DLT diagnostic evidence"], ["BLF: ANALYZED", "PCAP: ANALYZED", "MF4: ANALYZED", "Vehicle Identity"]),
        ({"pcap": PCAP}, ["PCAP: ANALYZED", "Network communication: OBSERVED", "Dominant observed protocol: HOMEPLUG_AV", "DIN 70121: OBSERVED", "DIN 70121 progression: CurrentDemand", "ISO 15118 / TLS: OBSERVED", "TLS version: TLS 1.2"], ["BLF: ANALYZED", "DLT: ANALYZED", "MF4: ANALYZED", "Vehicle Identity", "structured analysis: AVAILABLE"]),
        ({"mf4": MF4}, ["MF4: ANALYZED", "Charging progression: NOT_OBSERVED"], ["BLF: ANALYZED", "DLT: ANALYZED", "PCAP: ANALYZED", "Vehicle Identity"]),
        ({"vehicle_identity": VEHICLE, "blf": BLF, "dlt": DLT}, ["BLF: ANALYZED", "DLT: ANALYZED"], ["PCAP: ANALYZED", "MF4: ANALYZED"]),
        ({"vehicle_identity": VEHICLE, "blf": BLF, "mf4": MF4}, ["BLF: ANALYZED", "MF4: ANALYZED", "SUPPORTED_BY_MULTIPLE_TRACES"], ["DLT: ANALYZED", "PCAP: ANALYZED"]),
        ({"vehicle_identity": VEHICLE, "blf": BLF, "dlt": DLT, "pcap": PCAP, "mf4": MF4}, ["BLF: ANALYZED", "DLT: ANALYZED", "PCAP: ANALYZED", "MF4: ANALYZED", "SUPPORTED_BY_MULTIPLE_TRACES"], []),
    ],
)
def test_txt_subset_matrix(inputs, expected, unexpected) -> None:
    text = TestSessionSummaryService().generate_summary(**inputs)

    assert "Vehicle Test Session Engineering Summary" in text
    assert "Input traces are treated as belonging to the same vehicle and testing session." in text
    for value in expected:
        assert value in text
    for value in unexpected:
        assert value not in text


def test_zero_trace_input_is_rejected_by_txt_and_html() -> None:
    with pytest.raises(ValueError, match="No supported traces were provided"):
        TestSessionSummaryService().generate_summary()

    with pytest.raises(ValueError, match="No supported traces were provided"):
        SessionHtmlReportService().generate_report({}, MANIFEST)
