# models/blf_inventory.py

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class CanIdStatistic:
    """
    Statistics for a single CAN arbitration ID.
    """

    arbitration_id: int
    frame_count: int
    channel: int | None = None
    is_extended_id: bool = False


@dataclass(slots=True)
class BlfInventory:
    """
    Inventory and summary statistics for a BLF trace.
    """

    total_frames: int = 0

    unique_can_ids: int = 0

    standard_frame_count: int = 0
    extended_frame_count: int = 0

    channels: list[int] = field(
        default_factory=list
    )

    start_timestamp: datetime | None = None
    end_timestamp: datetime | None = None

    can_id_statistics: list[CanIdStatistic] = field(
        default_factory=list
    )

    @property
    def duration_seconds(self) -> float:
        """
        Calculate trace duration in seconds.
        """

        if (
            self.start_timestamp is None
            or self.end_timestamp is None
        ):
            return 0.0

        return (
            self.end_timestamp
            - self.start_timestamp
        ).total_seconds()

    @property
    def top_can_ids(self) -> list:
        return sorted(
            self.can_id_statistics,
            key=lambda item: item.frame_count,
            reverse=True,
        )