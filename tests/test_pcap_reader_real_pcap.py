from datetime import datetime, timezone
from pathlib import Path

import pytest

from readers.pcap_reader import PcapReader


PCAP_FILE = Path(
    "data",
    "pcap",
    "20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap",
)

EXPECTED_EVENT_COUNT = 45868
EXPECTED_SRC_MAC = "02:ab:01:d9:13:03"
EXPECTED_DST_MAC = "00:00:ff:ff:00:ff"
EXPECTED_ETHERTYPE = 0x88E1


def get_real_pcap():
    if not PCAP_FILE.exists():
        pytest.skip(f"Real PCAP file not available: {PCAP_FILE}")

    return PCAP_FILE


@pytest.fixture(scope="module")
def trace():
    return PcapReader().read(get_real_pcap())


def test_real_pcap_event_count(trace):
    assert trace.event_count == EXPECTED_EVENT_COUNT
    assert trace.metadata.event_count == EXPECTED_EVENT_COUNT
    assert not trace.is_empty


def test_real_pcap_metadata(trace):
    file_path = get_real_pcap()

    assert trace.metadata.file_path == file_path
    assert trace.metadata.file_name == file_path.name
    assert trace.metadata.trace_type == "PCAP"
    assert trace.metadata.file_size_bytes == file_path.stat().st_size


def test_real_pcap_timestamps(trace):
    assert trace.metadata.start_timestamp == datetime(
        2025,
        4,
        1,
        17,
        57,
        1,
        62925,
        tzinfo=timezone.utc,
    )

    assert trace.metadata.end_timestamp == datetime(
        2025,
        4,
        1,
        18,
        18,
        4,
        331274,
        tzinfo=timezone.utc,
    )

    assert trace.events[0].timestamp == trace.metadata.start_timestamp
    assert trace.events[-1].timestamp == trace.metadata.end_timestamp


def test_real_pcap_timestamps_are_ordered(trace):
    timestamps = [event.timestamp for event in trace.events]

    assert timestamps == sorted(timestamps)


def test_real_pcap_source_type(trace):
    assert all(
        event.source_type == "PCAP"
        for event in trace.events
    )


def test_real_pcap_homeplug_protocol(trace):
    assert all(
        event.event_name == "HOMEPLUG_AV"
        for event in trace.events
    )

    assert all(
        event.payload["protocol"] == "HOMEPLUG_AV"
        for event in trace.events
    )


def test_real_pcap_homeplug_ethertype(trace):
    assert all(
        event.payload["ether_type"] == EXPECTED_ETHERTYPE
        for event in trace.events
    )


def test_real_pcap_mac_pair(trace):
    assert all(
        event.payload["src_mac"] == EXPECTED_SRC_MAC
        for event in trace.events
    )

    assert all(
        event.payload["dst_mac"] == EXPECTED_DST_MAC
        for event in trace.events
    )


def test_real_pcap_preserves_raw_frames(trace):
    assert all(
        isinstance(event.payload["raw_data"], bytes)
        for event in trace.events
    )

    assert all(
        event.payload["captured_length"]
        == len(event.payload["raw_data"])
        for event in trace.events
    )


def test_real_pcap_preserves_ethernet_payload(trace):
    assert all(
        isinstance(event.payload["ethernet_payload"], bytes)
        for event in trace.events
    )

    assert all(
        event.payload["ethernet_payload_length"]
        == len(event.payload["ethernet_payload"])
        for event in trace.events
    )


def test_real_pcap_first_packet(trace):
    event = trace.events[0]

    assert event.event_name == "HOMEPLUG_AV"
    assert event.payload["protocol"] == "HOMEPLUG_AV"
    assert event.payload["src_mac"] == EXPECTED_SRC_MAC
    assert event.payload["dst_mac"] == EXPECTED_DST_MAC
    assert event.payload["ether_type"] == EXPECTED_ETHERTYPE
    assert event.payload["captured_length"] == 1319
    assert event.payload["ethernet_payload_length"] == 1305

    assert event.payload["ethernet_payload"][:16] == bytes.fromhex(
        "01 14 a2 00 00 00 80 e1 "
        "00 00 00 00 b2 ff ff 05"
    )


def test_real_pcap_known_frame_sizes(trace):
    frame_sizes = {
        event.payload["captured_length"]
        for event in trace.events
    }

    assert 1319 in frame_sizes
    assert 1317 in frame_sizes
    assert 60 in frame_sizes
    assert 454 in frame_sizes
    assert 95 in frame_sizes
    assert 198 in frame_sizes
    assert 608 in frame_sizes