from pathlib import Path

import pytest

from models.processed_trace import ProcessedTrace
from readers.dlt_reader import DltReader


def test_supports_dlt_file() -> None:
    reader = DltReader()

    assert reader.supports(
        Path("sample.dlt")
    ) is True


def test_rejects_non_dlt_file() -> None:
    reader = DltReader()

    assert reader.supports(
        Path("sample.blf")
    ) is False


def test_missing_file_raises_exception() -> None:
    reader = DltReader()

    with pytest.raises(FileNotFoundError):
        reader.read(
            Path("does_not_exist.dlt")
        )


def test_read_returns_processed_trace(
    tmp_path,
) -> None:
    trace_file = tmp_path / "sample.dlt"
    trace_file.write_bytes(b"")

    reader = DltReader()

    result = reader.read(trace_file)

    assert isinstance(
        result,
        ProcessedTrace,
    )


def test_metadata_trace_type(
    tmp_path,
) -> None:
    trace_file = tmp_path / "sample.dlt"
    trace_file.write_bytes(b"")

    reader = DltReader()

    result = reader.read(trace_file)

    assert (
        result.metadata.trace_type
        == "DLT"
    )


def test_metadata_file_name(
    tmp_path,
) -> None:
    trace_file = tmp_path / "vehicle_trace.dlt"
    trace_file.write_bytes(b"")

    reader = DltReader()

    result = reader.read(trace_file)

    assert (
        result.metadata.file_name
        == "vehicle_trace.dlt"
    )


def test_empty_file_creates_empty_trace(
    tmp_path,
) -> None:
    trace_file = tmp_path / "sample.dlt"
    trace_file.write_bytes(b"")

    reader = DltReader()

    result = reader.read(trace_file)

    assert result.event_count == 0
    assert result.is_empty is True