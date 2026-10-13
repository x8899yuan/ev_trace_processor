from datetime import datetime
from pathlib import Path

from models.processed_trace import ProcessedTrace
from models.trace_event import TraceEvent
from models.trace_metadata import TraceMetadata


def create_metadata() -> TraceMetadata:
    return TraceMetadata(
        file_path=Path("sample.blf"),
        trace_type="BLF",
        file_size_bytes=1024,
    )


def create_event() -> TraceEvent:
    return TraceEvent(
        timestamp=datetime(2026, 10, 1, 8, 0, 0),
        source_type="BLF",
        event_name="CAN_FRAME",
    )


def test_new_processed_trace_is_empty() -> None:
    trace = ProcessedTrace(
        metadata=create_metadata(),
    )

    assert trace.is_empty is True
    assert trace.event_count == 0


def test_add_event() -> None:
    trace = ProcessedTrace(
        metadata=create_metadata(),
    )

    trace.add_event(create_event())

    assert trace.is_empty is False
    assert trace.event_count == 1


def test_add_multiple_events() -> None:
    trace = ProcessedTrace(
        metadata=create_metadata(),
    )

    trace.add_event(create_event())
    trace.add_event(create_event())

    assert trace.event_count == 2


def test_clear_events() -> None:
    trace = ProcessedTrace(
        metadata=create_metadata(),
    )

    trace.add_event(create_event())
    trace.add_event(create_event())

    trace.clear_events()

    assert trace.is_empty is True
    assert trace.event_count == 0


def test_to_dict_empty_trace() -> None:
    trace = ProcessedTrace(
        metadata=create_metadata(),
    )

    result = trace.to_dict()

    assert result["event_count"] == 0
    assert result["events"] == []


def test_to_dict_with_events() -> None:
    trace = ProcessedTrace(
        metadata=create_metadata(),
    )

    trace.add_event(create_event())

    result = trace.to_dict()

    assert result["event_count"] == 1
    assert len(result["events"]) == 1


def test_metadata_is_preserved() -> None:
    metadata = create_metadata()

    trace = ProcessedTrace(
        metadata=metadata,
    )

    assert trace.metadata is metadata