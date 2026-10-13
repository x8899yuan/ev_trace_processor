from pathlib import Path

import pytest

from models.processed_trace import ProcessedTrace
from services.trace_processing_service import (
    TraceProcessingService,
)


def test_process_blf_file(
    tmp_path,
) -> None:
    trace_file = tmp_path / "vehicle_trace.blf"
    trace_file.write_bytes(b"")

    service = TraceProcessingService()

    result = service.process(trace_file)

    assert isinstance(
        result,
        ProcessedTrace,
    )

    assert (
        result.metadata.trace_type
        == "BLF"
    )


def test_process_pcap_file(
    tmp_path,
) -> None:
    trace_file = tmp_path / "network_capture.pcap"
    trace_file.write_bytes(b"")

    service = TraceProcessingService()

    result = service.process(trace_file)

    assert isinstance(
        result,
        ProcessedTrace,
    )

    assert (
        result.metadata.trace_type
        == "PCAP"
    )


def test_process_dlt_file(
    tmp_path,
) -> None:
    trace_file = tmp_path / "vehicle_trace.dlt"
    trace_file.write_bytes(b"")

    service = TraceProcessingService()

    result = service.process(trace_file)

    assert isinstance(
        result,
        ProcessedTrace,
    )

    assert (
        result.metadata.trace_type
        == "DLT"
    )


def test_unsupported_file_raises_value_error() -> None:
    service = TraceProcessingService()

    with pytest.raises(ValueError):
        service.process(
            Path("unsupported.xyz")
        )


def test_blf_file_name_preserved(
    tmp_path,
) -> None:
    trace_file = tmp_path / "vehicle_trace.blf"
    trace_file.write_bytes(b"")

    service = TraceProcessingService()

    result = service.process(trace_file)

    assert (
        result.metadata.file_name
        == "vehicle_trace.blf"
    )


def test_empty_file_returns_empty_trace(
    tmp_path,
) -> None:
    trace_file = tmp_path / "empty_trace.blf"
    trace_file.write_bytes(b"")

    service = TraceProcessingService()

    result = service.process(trace_file)

    assert result.is_empty is True
    assert result.event_count == 0


def test_process_returns_processed_trace(
    tmp_path,
) -> None:
    trace_file = tmp_path / "sample.blf"
    trace_file.write_bytes(b"")

    service = TraceProcessingService()

    result = service.process(trace_file)

    assert type(result).__name__ == "ProcessedTrace"