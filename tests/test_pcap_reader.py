from datetime import timezone
from pathlib import Path

import dpkt
import pytest

from readers.pcap_reader import PcapReader


def create_test_pcap(file_path: Path) -> list[bytes]:
    packets = [
        b"\x00\x11\x22\x33\x44\x55\x66\x77",
        b"\xaa\xbb\xcc\xdd\xee\xff",
    ]

    with file_path.open("wb") as file:
        writer = dpkt.pcap.Writer(file)
        writer.writepkt(packets[0], ts=1700000000.0)
        writer.writepkt(packets[1], ts=1700000001.5)
        writer.close()

    return packets


def test_supports_pcap_extension():
    reader = PcapReader()

    assert reader.supports(Path("trace.pcap"))
    assert reader.supports(Path("trace.PCAP"))


def test_does_not_support_other_extensions():
    reader = PcapReader()

    assert not reader.supports(Path("trace.blf"))
    assert not reader.supports(Path("trace.dlt"))
    assert not reader.supports(Path("trace.txt"))


def test_read_missing_file_raises_file_not_found(tmp_path):
    reader = PcapReader()
    file_path = tmp_path / "missing.pcap"

    with pytest.raises(FileNotFoundError):
        reader.read(file_path)


def test_read_wrong_extension_raises_value_error(tmp_path):
    reader = PcapReader()
    file_path = tmp_path / "trace.blf"
    file_path.write_bytes(b"test")

    with pytest.raises(ValueError):
        reader.read(file_path)


def test_read_pcap_creates_metadata(tmp_path):
    reader = PcapReader()
    file_path = tmp_path / "test.pcap"
    create_test_pcap(file_path)

    trace = reader.read(file_path)

    assert trace.metadata.file_path == file_path
    assert trace.metadata.trace_type == "PCAP"
    assert trace.metadata.file_size_bytes == file_path.stat().st_size


def test_read_pcap_creates_events(tmp_path):
    reader = PcapReader()
    file_path = tmp_path / "test.pcap"
    packets = create_test_pcap(file_path)

    trace = reader.read(file_path)

    assert trace.event_count == 2
    assert not trace.is_empty

    first_event = trace.events[0]
    second_event = trace.events[1]

    assert first_event.source_type == "PCAP"
    assert second_event.source_type == "PCAP"

    assert first_event.event_name == "packet"
    assert second_event.event_name == "packet"

    assert first_event.payload["raw_data"] == packets[0]
    assert second_event.payload["raw_data"] == packets[1]

    assert first_event.payload["captured_length"] == len(packets[0])
    assert second_event.payload["captured_length"] == len(packets[1])


def test_read_pcap_preserves_timestamps(tmp_path):
    reader = PcapReader()
    file_path = tmp_path / "test.pcap"
    create_test_pcap(file_path)

    trace = reader.read(file_path)

    assert trace.events[0].timestamp.timestamp() == pytest.approx(
        1700000000.0
    )
    assert trace.events[1].timestamp.timestamp() == pytest.approx(
        1700000001.5
    )

    assert trace.events[0].timestamp.tzinfo == timezone.utc
    assert trace.events[1].timestamp.tzinfo == timezone.utc


def test_read_empty_pcap_returns_empty_trace(tmp_path):
    reader = PcapReader()
    file_path = tmp_path / "empty.pcap"

    with file_path.open("wb") as file:
        writer = dpkt.pcap.Writer(file)
        writer.close()

    trace = reader.read(file_path)

    assert trace.event_count == 0
    assert trace.is_empty