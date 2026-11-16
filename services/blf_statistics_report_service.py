from pathlib import Path

from models.blf_statistics import BlfStatistics


class BlfStatisticsReportService:
    def generate_report(self, statistics: BlfStatistics) -> str:
        lines = [
            "BLF Statistics Report",
            "=" * 50,
            "",
            f"Total Frames: {statistics.total_frames:,}",
            f"Duration (s): {statistics.duration_seconds:.3f}",
            f"Frames per Second: {statistics.frames_per_second:,.3f}",
            "",
            f"Unique CAN IDs: {statistics.unique_can_ids:,}",
            f"Channel Count: {statistics.channel_count:,}",
            "",
            f"Standard Frames: {statistics.standard_frame_count:,}",
            f"Extended Frames: {statistics.extended_frame_count:,}",
            f"Standard Frames (%): {statistics.standard_frame_percentage:.3f}",
            f"Extended Frames (%): {statistics.extended_frame_percentage:.3f}",
            "",
            f"Busiest CAN ID: 0x{statistics.busiest_can_id:X}" if statistics.busiest_can_id is not None else "Busiest CAN ID: N/A",
            f"Busiest CAN ID Frames: {statistics.busiest_can_id_frames:,}",
            f"Busiest Channel: {statistics.busiest_channel}" if statistics.busiest_channel is not None else "Busiest Channel: N/A",
            f"Busiest Channel Frames: {statistics.busiest_channel_frames:,}",
        ]
        return "\n".join(lines)

    def save_report(self, statistics: BlfStatistics, file_stem: str) -> Path:
        project_root = Path(__file__).resolve().parents[1]
        output_directory = project_root / "reports" / "blf"
        output_directory.mkdir(parents=True, exist_ok=True)
        output_path = output_directory / "blf_statistics.txt"
        output_path.write_text(self.generate_report(statistics), encoding="utf-8")
        return output_path
