from pathlib import Path

from models.blf_statistics import BlfStatistics


class BlfStatisticsCsvService:

    def export(
        self,
        statistics: BlfStatistics,
        output_path: Path,
    ) -> Path:

        lines: list[str] = [
            "Metric,Value",
            f"Total Frames,{statistics.total_frames}",
            f"Duration Seconds,{statistics.duration_seconds}",
            f"Frames Per Second,{statistics.frames_per_second}",
            f"Unique CAN IDs,{statistics.unique_can_ids}",
            f"Channel Count,{statistics.channel_count}",
            (
                f"Standard Frames,"
                f"{statistics.standard_frame_count}"
            ),
            (
                f"Extended Frames,"
                f"{statistics.extended_frame_count}"
            ),
            (
                f"Standard Frame Percentage,"
                f"{statistics.standard_frame_percentage}"
            ),
            (
                f"Extended Frame Percentage,"
                f"{statistics.extended_frame_percentage}"
            ),
            (
                f"Busiest CAN ID,"
                f"{hex(statistics.busiest_can_id)}"
                if statistics.busiest_can_id is not None
                else "Busiest CAN ID,N/A"
            ),
            (
                f"Busiest CAN ID Frames,"
                f"{statistics.busiest_can_id_frames}"
            ),
            (
                f"Busiest Channel,"
                f"{statistics.busiest_channel}"
            ),
            (
                f"Busiest Channel Frames,"
                f"{statistics.busiest_channel_frames}"
            ),
        ]

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path.write_text(
            "\n".join(lines),
            encoding="utf-8",
        )

        return output_path

    def save_csv(
        self,
        statistics: BlfStatistics,
        file_stem: str,
    ) -> Path:

        project_root = (
            Path(__file__)
            .resolve()
            .parents[1]
        )

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
            / f"{Path(file_stem).stem}_statistics.csv"
        )

        return self.export(
            statistics=statistics,
            output_path=output_path,
        )