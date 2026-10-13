from pathlib import Path

import pytest

from models.processed_trace import ProcessedTrace
from readers.blf_reader import BlfReader


def test_supports_blf_file() -> None:
    reader = BlfReader()

    assert reader.supports(
        Path("sample.blf")
    ) is True


def test_rejects_non_blf_file() -> None:
    reader = BlfReader()

    assert reader.supports(
        Path("sample.pcap")
    ) is False


def test_missing_file_raises_exception() -> None:
    reader = BlfReader()

    with pytest.raises(FileNotFoundError):
        reader.read(
            Path("does_not_exist.blf")
        )


def test_read_returns_processed_trace(
    tmp_path,
) -> None:
    trace_file = tmp_path / "sample.blf"
    trace_file.write_bytes(b"")

    reader = BlfReader()

    result = reader.read(trace_file)

    assert isinstance(
        result,
        ProcessedTrace,
    )


def test_metadata_trace_type(
    tmp_path,
) -> None:
    trace_file = tmp_path / "sample.blf"
    trace_file.write_bytes(b"")

    reader = BlfReader()

    result = reader.read(trace_file)

    assert (
        result.metadata.trace_type
        == "BLF"
    )


def test_metadata_file_name(
    tmp_path,
) -> None:
    trace_file = tmp_path / "vehicle.blf"
    trace_file.write_bytes(b"")

    reader = BlfReader()

    result = reader.read(trace_file)

    assert (
        result.metadata.file_name
        == "vehicle.blf"
    )


def test_empty_file_creates_empty_trace(
    tmp_path,
) -> None:
    trace_file = tmp_path / "sample.blf"
    trace_file.write_bytes(b"")

    reader = BlfReader()

    result = reader.read(trace_file)

    assert result.event_count == 0
    assert result.is_empty is True