from unittest.mock import patch

import pytest

from models.processed_trace import ProcessedTrace
from services.trace_processing_service import TraceProcessingService


class EmptyBLFReader:
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        return None

    def __iter__(self):
        return iter(())


def test_process_blf_file(tmp_path) -> None:
    trace_file = tmp_path / "vehicle_trace.blf"
    trace_file.write_bytes(b"")
    service = TraceProcessingService()

    with patch("readers.blf_reader.can.BLFReader", EmptyBLFReader):
        result = service.process(trace_file)

    assert isinstance(result, ProcessedTrace)
    assert result.metadata.trace_type == "BLF"


def test_process_pcap_file(tmp_path) -> None:
    trace_file = tmp_path / "vehicle_trace.pcap"
    trace_file.write_bytes(b"")
    service = TraceProcessingService()

    result = service.process(trace_file)

    assert isinstance(result, ProcessedTrace)
    assert result.metadata.trace_type == "PCAP"


def test_process_dlt_file(tmp_path) -> None:
    trace_file = tmp_path / "vehicle_trace.dlt"
    trace_file.write_bytes(b"")
    service = TraceProcessingService()

    result = service.process(trace_file)

    assert isinstance(result, ProcessedTrace)
    assert result.metadata.trace_type == "DLT"


def test_unsupported_file_raises_value_error(tmp_path) -> None:
    trace_file = tmp_path / "vehicle_trace.xyz"
    trace_file.write_bytes(b"")
    service = TraceProcessingService()

    with pytest.raises(ValueError):
        service.process(trace_file)


def test_blf_file_name_preserved(tmp_path) -> None:
    trace_file = tmp_path / "vehicle_trace.blf"
    trace_file.write_bytes(b"")
    service = TraceProcessingService()

    with patch("readers.blf_reader.can.BLFReader", EmptyBLFReader):
        result = service.process(trace_file)

    assert result.metadata.file_name == "vehicle_trace.blf"


def test_empty_file_returns_empty_trace(tmp_path) -> None:
    trace_file = tmp_path / "empty_trace.blf"
    trace_file.write_bytes(b"")
    service = TraceProcessingService()

    with patch("readers.blf_reader.can.BLFReader", EmptyBLFReader):
        result = service.process(trace_file)

    assert result.events == []
    assert result.metadata.event_count == 0
    assert result.metadata.start_timestamp is None
    assert result.metadata.end_timestamp is None


def test_process_returns_processed_trace(tmp_path) -> None:
    trace_file = tmp_path / "sample.blf"
    trace_file.write_bytes(b"")
    service = TraceProcessingService()

    with patch("readers.blf_reader.can.BLFReader", EmptyBLFReader):
        result = service.process(trace_file)

    assert isinstance(result, ProcessedTrace)
