from pathlib import Path

import pytest

from models.processed_trace import ProcessedTrace
from readers.pcap_reader import PcapReader


def test_supports_pcap_file() -> None:
    reader = PcapReader()

    assert reader.supports(
        Path("capture.pcap")
    ) is True


def test_rejects_non_pcap_file() -> None:
    reader = PcapReader()

    assert reader.supports(
        Path("capture.blf")
    ) is False


def test_missing_file_raises_exception() -> None:
    reader = PcapReader()

    with pytest.raises(FileNotFoundError):
        reader.read(
            Path("does_not_exist.pcap")
        )


def test_read_returns_processed_trace(
    tmp_path,
) -> None:
    trace_file = tmp_path / "capture.pcap"
    trace_file.write_bytes(b"")

    reader = PcapReader()

    result = reader.read(trace_file)

    assert isinstance(
        result,
        ProcessedTrace,
    )


def test_metadata_trace_type(
    tmp_path,
) -> None:
    trace_file = tmp_path / "capture.pcap"
    trace_file.write_bytes(b"")

    reader = PcapReader()

    result = reader.read(trace_file)

    assert (
        result.metadata.trace_type
        == "PCAP"
    )


def test_metadata_file_name(
    tmp_path,
) -> None:
    trace_file = tmp_path / "network_capture.pcap"
    trace_file.write_bytes(b"")

    reader = PcapReader()

    result = reader.read(trace_file)

    assert (
        result.metadata.file_name
        == "network_capture.pcap"
    )