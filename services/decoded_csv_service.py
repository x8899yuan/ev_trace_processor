from pathlib import Path

from models.decoded_can_message import (
    DecodedCanMessage,
)


class DecodedCsvService:

    def export(
        self,
        decoded_messages: list[
            DecodedCanMessage
        ],
        output_path: Path,
    ) -> Path:

        lines: list[str] = [
            (
                "Timestamp,"
                "Channel,"
                "CAN_ID,"
                "Message,"
                "Signal,"
                "Value"
            )
        ]

        for message in decoded_messages:

            for (
                signal_name,
                value,
            ) in message.signals.items():

                lines.append(
                    (
                        f"{message.timestamp},"
                        f"{message.channel},"
                        f"0x{message.can_id:X},"
                        f"{message.message_name},"
                        f"{signal_name},"
                        f"{value}"
                    )
                )

        output_path.write_text(
            "\n".join(lines),
            encoding="utf-8",
        )

        return output_path

    def save_csv(
        self,
        decoded_messages: list[
            DecodedCanMessage
        ],
        report_name: str,
    ) -> Path:

        reports_dir = (
            Path("reports")
            / "decoded"
        )

        reports_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path = (
            reports_dir
            / f"{report_name}.csv"
        )

        return self.export(
            decoded_messages,
            output_path,
        )