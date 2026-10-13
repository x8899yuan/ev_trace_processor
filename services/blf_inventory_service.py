from collections import defaultdict

from models.blf_inventory import (
    BlfInventory,
    CanIdStatistic,
)
from models.processed_trace import ProcessedTrace


class BlfInventoryService:

    def analyze(
        self,
        trace: ProcessedTrace,
    ) -> BlfInventory:

        id_counts: dict[int, int] = defaultdict(int)
        id_channels: dict[int, int] = {}
        id_extended: dict[int, bool] = {}

        standard_frames = 0
        extended_frames = 0

        channels: set[int] = set()

        for event in trace.events:

            arbitration_id = event.payload["arbitration_id"]
            channel = event.payload["channel"]
            is_extended_id = event.payload["is_extended_id"]

            id_counts[arbitration_id] += 1

            id_channels.setdefault(
                arbitration_id,
                channel,
            )

            id_extended.setdefault(
                arbitration_id,
                is_extended_id,
            )

            channels.add(channel)

            if is_extended_id:
                extended_frames += 1
            else:
                standard_frames += 1

        can_id_statistics = [
            CanIdStatistic(
                arbitration_id=arbitration_id,
                frame_count=count,
                channel=id_channels[arbitration_id],
                is_extended_id=id_extended[arbitration_id],
            )
            for arbitration_id, count in id_counts.items()
        ]

        return BlfInventory(
            total_frames=len(trace.events),
            unique_can_ids=len(id_counts),
            standard_frame_count=standard_frames,
            extended_frame_count=extended_frames,
            channels=sorted(channels),
            start_timestamp=trace.metadata.start_timestamp,
            end_timestamp=trace.metadata.end_timestamp,
            can_id_statistics=can_id_statistics,
        )