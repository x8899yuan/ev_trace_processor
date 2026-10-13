from pathlib import Path

from models.blf_inventory import BlfInventory


class BlfInventoryReportService:

    def generate_report(
        self,
        inventory: BlfInventory,
        top_count: int = 20,
    ) -> str:

        lines: list[str] = []

        lines.append("BLF Inventory Report")
        lines.append("=" * 50)
        lines.append("")

        lines.append(
            f"Total Frames: {inventory.total_frames:,}"
        )

        lines.append(
            f"Unique CAN IDs: {inventory.unique_can_ids:,}"
        )

        lines.append(
            f"Standard Frames: {inventory.standard_frame_count:,}"
        )

        lines.append(
            f"Extended Frames: {inventory.extended_frame_count:,}"
        )

        lines.append(
            f"Channels: {inventory.channels}"
        )

        lines.append(
            f"Duration (s): {inventory.duration_seconds:.3f}"
        )

        lines.append("")

        lines.append("Top CAN IDs")
        lines.append("-" * 50)

        for stat in inventory.top_can_ids[:top_count]:

            lines.append(
                f"0x{stat.arbitration_id:X} | "
                f"{stat.frame_count:,} frames | "
                f"channel {stat.channel} | "
                f"extended={stat.is_extended_id}"
            )

        return "\n".join(lines)

    def save_report(
        self,
        inventory: BlfInventory,
        file_stem: str,
        top_count: int = 20,
    ) -> Path:

        project_root = Path(__file__).resolve().parents[1]

        output_directory = (
            project_root
            / "reports"
            / "inventory"
        )

        output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path = (
            output_directory
            / f"{Path(file_stem).stem}_inventory.txt"
        )

        output_path.write_text(
            self.generate_report(
                inventory,
                top_count,
            ),
            encoding="utf-8",
        )

        return output_path