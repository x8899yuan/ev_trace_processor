from pathlib import Path

import pytest

from services.session_trace_handlers import SessionTraceHandlers


BLF_FILES = sorted(Path("data/blf").glob("*.blf"))
DLT_FILES = sorted(Path("data/dlt").glob("*.dlt"))
PCAP_DIR = Path("data/pcap")
PCAP_FILES = sorted(
    path
    for path in PCAP_DIR.iterdir()
    if PCAP_DIR.exists() and path.is_file() and path.suffix.lower() in {".pcap", ".pcapng"}
) if PCAP_DIR.exists() else []
MF4_DIR = Path("data/MF4")
MF4_FILES = sorted(
    path
    for path in MF4_DIR.iterdir()
    if path.is_file() and path.suffix.lower() == ".mf4"
) if MF4_DIR.exists() else []


def test_real_bundle_discovery_matches_expected_active_inputs() -> None:
    assert len(BLF_FILES) == 1
    assert len(DLT_FILES) >= 1
    assert len(MF4_FILES) == 1


def test_real_bundle_blf_handler() -> None:
    result = SessionTraceHandlers().handle_blf(BLF_FILES)
    assert result["source_file"] == str(BLF_FILES[0])
    assert result["root_cause_status"] == "UNCONFIRMED"
    assert "charging_analysis" in result
    assert Path("reports/blf/blf_analysis_report.txt").exists()
    assert Path("reports/blf/blf_case_summary.txt").exists()
    vehicle = result.get("vehicle_identity")
    assert vehicle is not None
    assert vehicle["vin"] == "1V2ZZZE81TC000011"
    assert vehicle["source"] == "BLF / VIN_01"


def test_real_bundle_dlt_handler() -> None:
    result = SessionTraceHandlers().handle_dlt(DLT_FILES)
    assert result["capture"]["trace_count"] == len(DLT_FILES)
    assert result["capture"]["event_count"] > 0
    assert set(result["capture"]["source_files"]) == {path.name for path in DLT_FILES}
    assert Path("reports/dlt/dlt_analysis_report.txt").exists()
    assert Path("reports/dlt/dlt_case_summary.txt").exists()
    assert Path("reports/dlt/dlt_inventory.txt").exists()
    assert Path("reports/dlt/dlt_statistics.txt").exists()


def test_real_bundle_mf4_handler() -> None:
    result = SessionTraceHandlers().handle_mf4(MF4_FILES)
    assert result["source_file"] == str(MF4_FILES[0])
    assert result["charging_progression"] == "NOT_OBSERVED"
    assert result["connector_recognition"] == "NOT_RECOGNIZED"
    assert result["control_pilot_recognition"] == "NOT_ESTABLISHED"
    assert result["root_cause_status"] == "UNCONFIRMED"
    assert Path("reports/mf4/mf4_analysis_report.txt").exists()
    assert Path("reports/mf4/mf4_case_summary.txt").exists()


def test_real_bundle_pcap_handler_preserves_each_capture() -> None:
    if not PCAP_FILES:
        pytest.skip("No PCAP fixture is present in the active real-trace bundle")
    result = SessionTraceHandlers().handle_pcap(PCAP_FILES)
    assert len(result["captures"]) == len(PCAP_FILES)
    assert result["analysis"]["capture"]["packet_count"] > 0
    assert set(result["analysis"]["capture"]["source_files"]) == {str(path) for path in PCAP_FILES}
    assert result["din70121"]["capture_count"] == len(PCAP_FILES)
    assert result["iso15118_tls"]["capture_count"] == len(PCAP_FILES)
    for path in PCAP_FILES:
        generic_dir = Path("reports/pcap") / path.stem
        assert (generic_dir / "pcap_analysis_report.txt").exists()
        assert (generic_dir / "pcap_case_summary.txt").exists()
