from pathlib import Path
from unittest.mock import patch

import pytest

from models.processed_trace import ProcessedTrace
from readers.blf_reader import BlfReader


class EmptyBLFReader:
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        return None

    def __iter__(self):
        return iter(())


def test_supports_blf_file() -> None:
    reader = BlfReader()
    assert reader.supports(Path("sample.blf"))


def test_rejects_non_blf_file() -> None:
    reader = BlfReader()
    assert not reader.supports(Path("sample.pcap"))


def test_missing_file_raises_exception(tmp_path) -> None:
    reader = BlfReader()
    trace_file = tmp_path / "missing.blf"

    with pytest.raises(FileNotFoundError):
        reader.read(trace_file)


def test_read_returns_processed_trace(tmp_path) -> None:
    trace_file = tmp_path / "sample.blf"
    trace_file.write_bytes(b"")
    reader = BlfReader()

    with patch("readers.blf_reader.can.BLFReader", EmptyBLFReader):
        result = reader.read(trace_file)

    assert isinstance(result, ProcessedTrace)


def test_metadata_trace_type(tmp_path) -> None:
    trace_file = tmp_path / "sample.blf"
    trace_file.write_bytes(b"")
    reader = BlfReader()

    with patch("readers.blf_reader.can.BLFReader", EmptyBLFReader):
        result = reader.read(trace_file)

    assert result.metadata.trace_type == "BLF"


def test_metadata_file_name(tmp_path) -> None:
    trace_file = tmp_path / "vehicle.blf"
    trace_file.write_bytes(b"")
    reader = BlfReader()

    with patch("readers.blf_reader.can.BLFReader", EmptyBLFReader):
        result = reader.read(trace_file)

    assert result.metadata.file_name == "vehicle.blf"


def test_empty_file_creates_empty_trace(tmp_path) -> None:
    trace_file = tmp_path / "sample.blf"
    trace_file.write_bytes(b"")
    reader = BlfReader()

    with patch("readers.blf_reader.can.BLFReader", EmptyBLFReader):
        result = reader.read(trace_file)

    assert result.events == []
    assert result.metadata.event_count == 0
    assert result.metadata.start_timestamp is None
    assert result.metadata.end_timestamp is None
