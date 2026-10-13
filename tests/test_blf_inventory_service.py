from datetime import datetime
from pathlib import Path

from models.blf_inventory import CanIdStatistic
from models.processed_trace import ProcessedTrace
from models.trace_event import TraceEvent
from models.trace_metadata import TraceMetadata
from services.blf_inventory_service import BlfInventoryService


def create_trace() -> ProcessedTrace:

    metadata = TraceMetadata(
        file_path=Path("test.blf"),
        trace_type="BLF",
        file_size_bytes=100,
        start_timestamp=datetime(2025, 1, 1, 0, 0, 0),
        end_timestamp=datetime(2025, 1, 1, 0, 0, 10),
        event_count=3,
    )

    events = [
        TraceEvent(
            timestamp=datetime.now(),
            source_type="BLF",
            event_name="CAN_FRAME",
            payload={
                "channel": 1,
                "arbitration_id": 100,
                "is_extended_id": False,
            },
        ),
        TraceEvent(
            timestamp=datetime.now(),
            source_type="BLF",
            event_name="CAN_FRAME",
            payload={
                "channel": 1,
                "arbitration_id": 100,
                "is_extended_id": False,
            },
        ),
        TraceEvent(
            timestamp=datetime.now(),
            source_type="BLF",
            event_name="CAN_FRAME",
            payload={
                "channel": 2,
                "arbitration_id": 200,
                "is_extended_id": True,
            },
        ),
    ]

    return ProcessedTrace(
        metadata=metadata,
        events=events,
    )


def test_total_frames() -> None:

    inventory = BlfInventoryService().analyze(
        create_trace()
    )

    assert inventory.total_frames == 3


def test_unique_can_ids() -> None:

    inventory = BlfInventoryService().analyze(
        create_trace()
    )

    assert inventory.unique_can_ids == 2


def test_standard_frame_count() -> None:

    inventory = BlfInventoryService().analyze(
        create_trace()
    )

    assert inventory.standard_frame_count == 2


def test_extended_frame_count() -> None:

    inventory = BlfInventoryService().analyze(
        create_trace()
    )

    assert inventory.extended_frame_count == 1


def test_channels() -> None:

    inventory = BlfInventoryService().analyze(
        create_trace()
    )

    assert inventory.channels == [1, 2]


def test_can_id_statistics_created() -> None:

    inventory = BlfInventoryService().analyze(
        create_trace()
    )

    assert len(inventory.can_id_statistics) == 2


def test_can_id_100_count() -> None:

    inventory = BlfInventoryService().analyze(
        create_trace()
    )

    stats = {
        s.arbitration_id: s.frame_count
        for s in inventory.can_id_statistics
    }

    assert stats[100] == 2


def test_can_id_200_count() -> None:

    inventory = BlfInventoryService().analyze(
        create_trace()
    )

    stats = {
        s.arbitration_id: s.frame_count
        for s in inventory.can_id_statistics
    }

    assert stats[200] == 1