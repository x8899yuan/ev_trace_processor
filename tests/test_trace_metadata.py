from datetime import datetime
from pathlib import Path

from models.trace_metadata import TraceMetadata


def test_file_name_property() -> None:
    metadata = TraceMetadata(
        file_path=Path("sample.blf"),
        trace_type="BLF",
        file_size_bytes=1024,
    )

    assert metadata.file_name == "sample.blf"


def test_has_events_false_when_event_count_zero() -> None:
    metadata = TraceMetadata(
        file_path=Path("sample.blf"),
        trace_type="BLF",
        file_size_bytes=1024,
    )

    assert metadata.has_events is False


def test_has_events_true_when_event_count_greater_than_zero() -> None:
    metadata = TraceMetadata(
        file_path=Path("sample.blf"),
        trace_type="BLF",
        file_size_bytes=1024,
        event_count=10,
    )

    assert metadata.has_events is True


def test_duration_seconds_returns_none_without_timestamps() -> None:
    metadata = TraceMetadata(
        file_path=Path("sample.blf"),
        trace_type="BLF",
        file_size_bytes=1024,
    )

    assert metadata.duration_seconds is None


def test_duration_seconds_calculation() -> None:
    metadata = TraceMetadata(
        file_path=Path("sample.blf"),
        trace_type="BLF",
        file_size_bytes=1024,
        start_timestamp=datetime(2026, 10, 1, 8, 0, 0),
        end_timestamp=datetime(2026, 10, 1, 8, 15, 0),
    )

    assert metadata.duration_seconds == 900.0


def test_to_dict() -> None:
    metadata = TraceMetadata(
        file_path=Path("sample.blf"),
        trace_type="BLF",
        file_size_bytes=1024,
        event_count=100,
    )

    result = metadata.to_dict()

    assert result["file_name"] == "sample.blf"
    assert result["trace_type"] == "BLF"
    assert result["file_size_bytes"] == 1024
    assert result["event_count"] == 100


def test_to_dict_without_timestamps() -> None:
    metadata = TraceMetadata(
        file_path=Path("sample.blf"),
        trace_type="BLF",
        file_size_bytes=1024,
    )

    result = metadata.to_dict()

    assert result["start_timestamp"] is None
    assert result["end_timestamp"] is None
    assert result["duration_seconds"] is None