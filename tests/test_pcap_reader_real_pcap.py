from datetime import timezone
from pathlib import Path

from readers.pcap_reader import PcapReader


PCAP_FILE = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "pcap"
    / "20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap"
)


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

    for event in trace.events:
        assert event.source_type == "PCAP"
        assert event.event_name == "packet"
        assert event.timestamp.tzinfo == timezone.utc

        assert "raw_data" in event.payload
        assert "captured_length" in event.payload

        raw_data = event.payload["raw_data"]
        captured_length = event.payload["captured_length"]

        assert isinstance(raw_data, bytes)
        assert captured_length == len(raw_data)
        assert captured_length > 0

        if previous_timestamp is not None:
            assert event.timestamp >= previous_timestamp

        previous_timestamp = event.timestamp