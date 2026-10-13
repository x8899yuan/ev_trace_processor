from pathlib import Path


class ChargingEventReportService:

    REPORT_PATH = Path(
        "reports/charging/charging_event_report.txt"
    )

    def generate_report(
        self,
        detected_events: list[dict],
    ) -> str:

        self.REPORT_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        lines = []

        lines.append(
            "CHARGING EVENT REPORT"
        )

        lines.append("=" * 80)

        lines.append("")

        if not detected_events:

            lines.append(
                "No charging events detected."
            )

        else:

            for event in detected_events:

                lines.append(
                    str(event["timestamp"])
                )

                lines.append(
                    f"Signal: "
                    f"{event['signal']}"
                )

                lines.append(
                    f"Value: "
                    f"{event['value']}"
                )

                lines.append(
                    f"Event: "
                    f"{event['description']}"
                )

                lines.append("")

        self.REPORT_PATH.write_text(
            "\n".join(lines),
            encoding="utf-8",
        )

        return str(self.REPORT_PATH)