from pathlib import Path

from models.blf_statistics import BlfStatistics


class BlfStatisticsReportService:

    def generate_report(
        self,
        statistics: BlfStatistics,
    ) -> str:

        lines: list[str] = []

        lines.append("BLF Statistics Report")
        lines.append("=" * 50)
        lines.append("")

        lines.append(
            f"Total Frames: "
            f"{statistics.total_frames:,}"
        )

        lines.append(
            f"Duration (s): "
            f"{statistics.duration_seconds:.3f}"
        )

        lines.append(
            f"Frames per Second: "
            f"{statistics.frames_per_second:,.3f}"
        )

        lines.append("")

        lines.append(
            f"Unique CAN IDs: "
            f"{statistics.unique_can_ids:,}"
        )

        lines.append(
            f"Channel Count: "
            f"{statistics.channel_count:,}"
        )

        lines.append("")

        lines.append(
            f"Standard Frames: "
            f"{statistics.standard_frame_count:,}"
        )

        lines.append(
            f"Extended Frames: "
            f"{statistics.extended_frame_count:,}"
        )

        lines.append(
            f"Standard Frames (%): "
            f"{statistics.standard_frame_percentage:.3f}"
        )

        lines.append(
            f"Extended Frames (%): "
            f"{statistics.extended_frame_percentage:.3f}"
        )

        lines.append("")

        if statistics.busiest_can_id is not None:
            lines.append(
                f"Busiest CAN ID: "
                f"0x{statistics.busiest_can_id:X}"
            )
        else:
            lines.append(
                "Busiest CAN ID: N/A"
            )

        lines.append(
            f"Busiest CAN ID Frames: "
            f"{statistics.busiest_can_id_frames:,}"
        )

        if statistics.busiest_channel is not None:
            lines.append(
                f"Busiest Channel: "
                f"{statistics.busiest_channel}"
            )
        else:
            lines.append(
                "Busiest Channel: N/A"
            )

        lines.append(
            f"Busiest Channel Frames: "
            f"{statistics.busiest_channel_frames:,}"
        )

        return "\n".join(lines)

    def save_report(
        self,
        statistics: BlfStatistics,
        file_stem: str,
    ) -> Path:

        project_root = Path(__file__).resolve().parents[1]

        output_directory = (
            project_root
            / "reports"
            / "statistics"
        )

        output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path = (
            output_directory
            / f"{Path(file_stem).stem}_statistics.txt"
        )

        output_path.write_text(
            self.generate_report(
                statistics
            ),
            encoding="utf-8",
        )

        return output_path