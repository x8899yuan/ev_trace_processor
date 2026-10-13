from pathlib import Path

from models.blf_inventory import BlfInventory


class BlfInventoryCsvService:
    def export(
        self,
        inventory: BlfInventory,
        output_path: Path,
    ) -> Path:

        lines: list[str] = [
            "CAN_ID,Frames,Channel,Extended"
        ]

        for stat in inventory.top_can_ids:
            lines.append(
                f"0x{stat.arbitration_id:X},"
                f"{stat.frame_count},"
                f"{stat.channel},"
                f"{stat.is_extended_id}"
            )

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
        inventory: BlfInventory,
        file_stem: str,
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
            / f"{Path(file_stem).stem}_inventory.csv"
        )

        return self.export(
            inventory=inventory,
            output_path=output_path,
        )