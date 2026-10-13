from pathlib import Path

import pytest

from models.processed_trace import ProcessedTrace
from models.trace_metadata import TraceMetadata
from readers.base_reader import BaseReader


class DummyReader(BaseReader):
    def supports(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == ".dummy"

    def read(self, file_path: Path) -> ProcessedTrace:
        metadata = TraceMetadata(
            file_path=file_path,
            trace_type="DUMMY",
            file_size_bytes=0,
        )

        return ProcessedTrace(metadata=metadata)


def test_base_reader_cannot_be_instantiated() -> None:
    with pytest.raises(TypeError):
        BaseReader()


def test_dummy_reader_supports_dummy_extension() -> None:
    reader = DummyReader()

    assert reader.supports(Path("sample.dummy")) is True


def test_dummy_reader_rejects_other_extensions() -> None:
    reader = DummyReader()

    assert reader.supports(Path("sample.blf")) is False


def test_dummy_reader_read_returns_processed_trace() -> None:
    reader = DummyReader()

    result = reader.read(Path("sample.dummy"))

    assert isinstance(result, ProcessedTrace)


def test_dummy_reader_metadata_file_name() -> None:
    reader = DummyReader()

    result = reader.read(Path("sample.dummy"))

    assert result.metadata.file_name == "sample.dummy"


def test_dummy_reader_metadata_trace_type() -> None:
    reader = DummyReader()

    result = reader.read(Path("sample.dummy"))

    assert result.metadata.trace_type == "DUMMY"


def test_dummy_reader_returns_empty_trace() -> None:
    reader = DummyReader()

    result = reader.read(Path("sample.dummy"))

    assert result.event_count == 0
    assert result.is_empty is True