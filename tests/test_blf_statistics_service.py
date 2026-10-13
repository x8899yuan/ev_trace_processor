from datetime import datetime
from pathlib import Path

import pytest

from models.processed_trace import ProcessedTrace
from models.trace_event import TraceEvent
from models.trace_metadata import TraceMetadata
from services.blf_statistics_service import (
    BlfStatisticsService,
)


def test_statistics_analysis() -> None:

    start_timestamp = datetime(
        2025,
        1,
        1,
        0,
        0,
        0,
    )

    end_timestamp = datetime(
        2025,
        1,
        1,
        0,
        0,
        10,
    )

    metadata = TraceMetadata(
        file_path=Path("test.blf"),
        trace_type="BLF",
        file_size_bytes=1024,
        start_timestamp=start_timestamp,
        end_timestamp=end_timestamp,
        event_count=4,
    )

    events = [
        TraceEvent(
            timestamp=start_timestamp,
            source_type="BLF",
            event_name="CAN_FRAME",
            payload={
                "channel": 1,
                "arbitration_id": 0x100,
                "dlc": 8,
                "data": "",
                "is_extended_id": False,
            },
        ),
        TraceEvent(
            timestamp=start_timestamp,
            source_type="BLF",
            event_name="CAN_FRAME",
            payload={
                "channel": 1,
                "arbitration_id": 0x100,
                "dlc": 8,
                "data": "",
                "is_extended_id": False,
            },
        ),
        TraceEvent(
            timestamp=start_timestamp,
            source_type="BLF",
            event_name="CAN_FRAME",
            payload={
                "channel": 2,
                "arbitration_id": 0x200,
                "dlc": 8,
                "data": "",
                "is_extended_id": True,
            },
        ),
        TraceEvent(
            timestamp=start_timestamp,
            source_type="BLF",
            event_name="CAN_FRAME",
            payload={
                "channel": 1,
                "arbitration_id": 0x100,
                "dlc": 8,
                "data": "",
                "is_extended_id": False,
            },
        ),
    ]

    trace = ProcessedTrace(
        metadata=metadata,
        events=events,
    )

    statistics = (
        BlfStatisticsService()
        .analyze(trace)
    )

    assert statistics.total_frames == 4
    assert statistics.duration_seconds == 10.0

    assert statistics.frames_per_second == pytest.approx(
        0.4
    )

    assert statistics.unique_can_ids == 2

    assert statistics.standard_frame_count == 3
    assert statistics.extended_frame_count == 1

    assert (
        statistics.standard_frame_percentage
        == pytest.approx(75.0)
    )

    assert (
        statistics.extended_frame_percentage
        == pytest.approx(25.0)
    )

    assert statistics.channel_count == 2

    assert statistics.busiest_can_id == 0x100
    assert statistics.busiest_can_id_frames == 3

    assert statistics.busiest_channel == 1
    assert statistics.busiest_channel_frames == 3