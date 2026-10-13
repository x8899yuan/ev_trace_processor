from models.blf_statistics import BlfStatistics
from models.processed_trace import ProcessedTrace


class BlfStatisticsService:

    def analyze(
        self,
        trace: ProcessedTrace,
    ) -> BlfStatistics:

        total_frames = trace.event_count
        duration_seconds = (
            trace.metadata.duration_seconds
            or 0.0
        )

        frames_per_second = (
            total_frames / duration_seconds
            if duration_seconds > 0.0
            else 0.0
        )

        standard_frame_count = 0
        extended_frame_count = 0

        can_id_counts: dict[int, int] = {}
        channel_counts: dict[int, int] = {}

        for event in trace.events:

            arbitration_id = event.payload.get(
                "arbitration_id"
            )

            channel = event.payload.get(
                "channel"
            )

            is_extended_id = event.payload.get(
                "is_extended_id",
                False,
            )

            if is_extended_id:
                extended_frame_count += 1
            else:
                standard_frame_count += 1

            if isinstance(arbitration_id, int):
                can_id_counts[arbitration_id] = (
                    can_id_counts.get(
                        arbitration_id,
                        0,
                    )
                    + 1
                )

            if isinstance(channel, int):
                channel_counts[channel] = (
                    channel_counts.get(
                        channel,
                        0,
                    )
                    + 1
                )

        standard_frame_percentage = (
            standard_frame_count
            / total_frames
            * 100.0
            if total_frames > 0
            else 0.0
        )

        extended_frame_percentage = (
            extended_frame_count
            / total_frames
            * 100.0
            if total_frames > 0
            else 0.0
        )

        busiest_can_id = None
        busiest_can_id_frames = 0

        if can_id_counts:
            busiest_can_id = max(
                can_id_counts,
                key=lambda can_id: (
                    can_id_counts[can_id]
                ),
            )

            busiest_can_id_frames = (
                can_id_counts[busiest_can_id]
            )

        busiest_channel = None
        busiest_channel_frames = 0

        if channel_counts:
            busiest_channel = max(
                channel_counts,
                key=lambda channel_number: (
                    channel_counts[
                        channel_number
                    ]
                ),
            )

            busiest_channel_frames = (
                channel_counts[
                    busiest_channel
                ]
            )

        return BlfStatistics(
            total_frames=total_frames,
            duration_seconds=duration_seconds,
            frames_per_second=frames_per_second,
            unique_can_ids=len(can_id_counts),
            standard_frame_count=standard_frame_count,
            extended_frame_count=extended_frame_count,
            standard_frame_percentage=(
                standard_frame_percentage
            ),
            extended_frame_percentage=(
                extended_frame_percentage
            ),
            channel_count=len(channel_counts),
            busiest_can_id=busiest_can_id,
            busiest_can_id_frames=(
                busiest_can_id_frames
            ),
            busiest_channel=busiest_channel,
            busiest_channel_frames=(
                busiest_channel_frames
            ),
        )