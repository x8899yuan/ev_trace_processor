from pathlib import Path

import pytest

from readers.blf_reader import BlfReader
from services.blf_statistics_service import (
    BlfStatisticsService,
)


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)


def test_real_blf_statistics() -> None:

    trace = BlfReader().read(
        BLF_FILE,
    )

    statistics = (
        BlfStatisticsService()
        .analyze(trace)
    )

    print()
    print("BLF Statistics")
    print("=" * 50)
    print(
        f"Total Frames: "
        f"{statistics.total_frames:,}"
    )
    print(
        f"Duration (s): "
        f"{statistics.duration_seconds:.3f}"
    )
    print(
        f"Frames per Second: "
        f"{statistics.frames_per_second:,.3f}"
    )
    print(
        f"Unique CAN IDs: "
        f"{statistics.unique_can_ids:,}"
    )
    print(
        f"Standard Frames: "
        f"{statistics.standard_frame_count:,}"
    )
    print(
        f"Extended Frames: "
        f"{statistics.extended_frame_count:,}"
    )
    print(
        f"Standard Frames (%): "
        f"{statistics.standard_frame_percentage:.3f}"
    )
    print(
        f"Extended Frames (%): "
        f"{statistics.extended_frame_percentage:.3f}"
    )
    print(
        f"Channel Count: "
        f"{statistics.channel_count:,}"
    )

    if statistics.busiest_can_id is not None:
        print(
            f"Busiest CAN ID: "
            f"0x{statistics.busiest_can_id:X}"
        )

    print(
        f"Busiest CAN ID Frames: "
        f"{statistics.busiest_can_id_frames:,}"
    )
    print(
        f"Busiest Channel: "
        f"{statistics.busiest_channel}"
    )
    print(
        f"Busiest Channel Frames: "
        f"{statistics.busiest_channel_frames:,}"
    )
    print()

    assert statistics.total_frames == trace.event_count

    assert statistics.total_frames > 0
    assert statistics.duration_seconds > 0.0
    assert statistics.frames_per_second > 0.0
    assert statistics.unique_can_ids > 0

    assert (
        statistics.standard_frame_count
        + statistics.extended_frame_count
        == statistics.total_frames
    )

    assert (
        statistics.standard_frame_percentage
        + statistics.extended_frame_percentage
        == pytest.approx(100.0)
    )

    assert statistics.channel_count > 0
    assert statistics.busiest_can_id is not None
    assert statistics.busiest_can_id_frames > 0
    assert statistics.busiest_channel is not None
    assert statistics.busiest_channel_frames > 0