from pathlib import Path


class ChargingEventReportService:
    REPORT_PATH = Path("reports/charging/charging_event_report.txt")

    def generate_report(self, detected_events: list[dict]) -> str:
        self.REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        lines = ["CHARGING EVENT REPORT", "=" * 80, ""]
        if not detected_events:
            lines.extend(["No charging observations detected.", ""])
        else:
            first_timestamp = self._timestamp(detected_events[0])
            for index, event in enumerate(detected_events, start=1):
                timestamp = self._timestamp(event)
                lines.extend([
                    f"Observation {index}",
                    "-" * 80,
                    f"Timestamp:     {self._format_timestamp(timestamp, event.get('timestamp'))}",
                    f"Relative time: {self._relative_time(timestamp, first_timestamp)}",
                    f"Signal:        {event.get('signal', 'Unknown')}",
                    f"Raw value:     {event.get('value', 'Unknown')}",
                    f"Meaning:       {event.get('description') or event.get('event') or 'Unknown condition'}",
                    "",
                ])
        self.REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
        return str(self.REPORT_PATH)

    def _timestamp(self, event):
        try:
            return float(event.get("timestamp"))
        except (TypeError, ValueError):
            return None

    def _relative_time(self, timestamp, first_timestamp):
        if timestamp is None or first_timestamp is None:
            return "Unknown"
        return f"+{timestamp - first_timestamp:.3f} s"

    def _format_timestamp(self, timestamp, raw_timestamp):
        if timestamp is None:
            return str(raw_timestamp) if raw_timestamp is not None else "Unknown"
        return f"{timestamp:.6f}"
