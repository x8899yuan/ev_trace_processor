from pathlib import Path

import pytest

from readers.pcap_reader import PcapReader
from services.iotecha_hpgp_decoder_service import IotechaHpgpDecoderService


PCAP_PATH = Path(r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap")

EXPECTED_SLAC_COUNTS = {
    "CM_SLAC_PARM.REQ": 1,
    "CM_SLAC_PARM.CNF": 1,
    "CM_START_ATTEN_CHAR.IND": 3,
    "CM_MNBC_SOUND.IND": 10,
    "CM_ATTEN_CHAR.IND": 1,
    "CM_ATTEN_CHAR.RSP": 1,
    "CM_SLAC_MATCH.REQ": 1,
    "CM_SLAC_MATCH.CNF": 1,
}


def load_real_records():
    if not PCAP_PATH.exists():
        pytest.skip(f"Optional legacy PCAP fixture is not available: {PCAP_PATH}")
    trace = PcapReader().read(PCAP_PATH)
    service = IotechaHpgpDecoderService()
    records = service.decode_trace(trace)
    return service, records


def collect_embedded_frames(records):
    return [
        (record, frame)
        for record in records
        for frame in record.get("embedded_frames", [])
    ]


def collect_slac_frames(records):
    return [
        (record, frame)
        for record, frame in collect_embedded_frames(records)
        if frame["protocol"] == "slac"
    ]


def test_decode_real_iotecha_hpgp_pcap():
    service, records = load_real_records()
    assert records
    summary = service.summarize(records)
    assert summary["record_count"] == len(records)
    assert summary["record_class_counts"]
    assert summary["payload_length_counts"]


def test_recover_real_embedded_homeplug_frames():
    _, records = load_real_records()
    embedded_frames = collect_embedded_frames(records)
    assert embedded_frames
    for _, frame in embedded_frames:
        assert frame["offset"] == 106
        assert frame["packet_offset"] == 120
        assert frame["ethertype"] == "0x88E1"
        assert frame["captured_length"] > 0
        assert isinstance(frame["data"], bytes)
        assert frame["data"]
        assert frame["destination_mac"]
        assert frame["source_mac"]
        assert frame["mmv"]
        assert frame["mmtype"]
        assert frame["sha256"]
        assert frame["boundary_source"] in {
            "analyzer_metadata",
            "measurement_status",
            "payload_end",
        }


def test_recover_real_slac_sequence():
    _, records = load_real_records()
    slac_frames = collect_slac_frames(records)
    assert slac_frames
    subtypes = [frame["subtype"] for _, frame in slac_frames]
    for subtype, minimum_count in EXPECTED_SLAC_COUNTS.items():
        assert subtypes.count(subtype) >= minimum_count
    first_positions = {subtype: subtypes.index(subtype) for subtype in EXPECTED_SLAC_COUNTS}
    assert first_positions["CM_SLAC_PARM.REQ"] < first_positions["CM_SLAC_PARM.CNF"]
    assert first_positions["CM_SLAC_PARM.CNF"] < first_positions["CM_START_ATTEN_CHAR.IND"]
    assert first_positions["CM_START_ATTEN_CHAR.IND"] < first_positions["CM_MNBC_SOUND.IND"]
    assert first_positions["CM_MNBC_SOUND.IND"] < first_positions["CM_ATTEN_CHAR.IND"]
    assert first_positions["CM_ATTEN_CHAR.IND"] < first_positions["CM_ATTEN_CHAR.RSP"]
    assert first_positions["CM_ATTEN_CHAR.RSP"] < first_positions["CM_SLAC_MATCH.REQ"]
    assert first_positions["CM_SLAC_MATCH.REQ"] < first_positions["CM_SLAC_MATCH.CNF"]


def test_real_slac_frames_have_consistent_structure():
    _, records = load_real_records()
    slac_frames = collect_slac_frames(records)
    assert slac_frames
    for _, frame in slac_frames:
        assert frame["offset"] == 106
        assert frame["packet_offset"] == 120
        assert frame["ethertype"] == "0x88E1"
        assert frame["mmv"] == "0x01"
        assert frame["confidence"] == 1.0
        assert frame["minimum_message_length"] >= 3
        data = frame["data"]
        assert len(data) >= 17
        assert int.from_bytes(data[12:14], "big") == 0x88E1


def test_real_slac_mac_relationships():
    _, records = load_real_records()
    slac_frames = collect_slac_frames(records)
    assert slac_frames
    mac_addresses = {
        address
        for _, frame in slac_frames
        for address in (frame["source_mac"], frame["destination_mac"])
    }
    assert "48:31:33:00:04:30" in mac_addresses
    assert "14:1f:ba:10:d0:85" in mac_addresses


def test_real_decoder_summary_contains_complete_slac_sequence():
    service, records = load_real_records()
    summary = service.summarize(records)
    assert summary["embedded_frame_count"] > 0
    assert summary["embedded_protocol_counts"].get("slac", 0) >= sum(EXPECTED_SLAC_COUNTS.values())
    subtype_counts = summary["embedded_subtype_counts"]
    for subtype, minimum_count in EXPECTED_SLAC_COUNTS.items():
        assert subtype_counts.get(subtype, 0) >= minimum_count
