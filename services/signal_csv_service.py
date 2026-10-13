from pathlib import Path


class SignalCsvService:

    def export(
        self,
        signal_data: list[dict],
        output_path: Path,
    ) -> Path:

        lines = [
            (
                "Timestamp,"
                "Channel,"
                "CAN_ID,"
                "Message,"
                "Signal,"
                "Value"
            )
        ]

        for entry in signal_data:

            lines.append(
                (
                    f"{entry['timestamp']},"
                    f"{entry['channel']},"
                    f"0x{entry['can_id']:X},"
                    f"{entry['message_name']},"
                    f"{entry['signal_name']},"
                    f"{entry['value']}"
                )
            )

        output_path.write_text(
            "\n".join(lines),
            encoding="utf-8",
        )

        return output_path

    def save_csv(
        self,
        signal_data: list[dict],
        signal_name: str,
    ) -> Path:

        reports_dir = (
            Path("reports")
            / "signals"
        )

        reports_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        safe_name = (
            signal_name
            .replace("/", "_")
            .replace("\\", "_")
            .replace(" ", "_")
        )

        output_path = (
            reports_dir
            / f"{safe_name}.csv"
        )

        return self.export(
            signal_data,
            output_path,
        )