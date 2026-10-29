from datetime import timezone
from pathlib import Path

from readers.pcap_reader import PcapReader


PCAP_FILE = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "pcap"
    / "20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap"
)

VALID_EVENT_NAMES = {
    "packet",
    "Ethernet",
    "ARP",
    "IPv4",
    "IPv6",
    "UDP",
    "TCP",
}


def test_pcap_reader_real_pcap():
    assert PCAP_FILE.exists()

    reader = PcapReader()
    assert reader.supports(PCAP_FILE)

    trace = reader.read(PCAP_FILE)

    assert trace.metadata.file_path == PCAP_FILE
    assert trace.metadata.trace_type == "PCAP"
    assert trace.metadata.file_size_bytes == PCAP_FILE.stat().st_size
    assert trace.event_count > 0
    assert not trace.is_empty

    previous_timestamp = None
    identified_protocol = False

    for event in trace.events:
        assert event.source_type == "PCAP"
        assert event.event_name in VALID_EVENT_NAMES
        assert event.timestamp.tzinfo == timezone.utc
        assert "raw_data" in event.payload
        assert "captured_length" in event.payload

        raw_data = event.payload["raw_data"]
        captured_length = event.payload["captured_length"]

        assert isinstance(raw_data, bytes)
        assert captured_length == len(raw_data)
        assert captured_length > 0

        if event.event_name != "packet":
            identified_protocol = True
            assert "protocol" in event.payload
            assert "src_mac" in event.payload
            assert "dst_mac" in event.payload
            assert "ether_type" in event.payload

        if event.event_name in {"IPv4", "IPv6", "UDP", "TCP"}:
            assert "network_protocol" in event.payload
            assert "src_ip" in event.payload
            assert "dst_ip" in event.payload

        if event.event_name in {"UDP", "TCP"}:
            assert "src_port" in event.payload
            assert "dst_port" in event.payload
            assert "transport_payload" in event.payload
            assert "transport_payload_length" in event.payload
            assert event.payload["transport_payload_length"] == len(
                event.payload["transport_payload"]
            )

        if previous_timestamp is not None:
            assert event.timestamp >= previous_timestamp

        previous_timestamp = event.timestamp

    assert identified_protocol
