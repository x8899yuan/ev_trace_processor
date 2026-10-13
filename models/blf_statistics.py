from dataclasses import dataclass


@dataclass(frozen=True)
class BlfStatistics:
    total_frames: int
    duration_seconds: float
    frames_per_second: float

    unique_can_ids: int

    standard_frame_count: int
    extended_frame_count: int

    standard_frame_percentage: float
    extended_frame_percentage: float

    channel_count: int

    busiest_can_id: int | None
    busiest_can_id_frames: int

    busiest_channel: int | None
    busiest_channel_frames: int