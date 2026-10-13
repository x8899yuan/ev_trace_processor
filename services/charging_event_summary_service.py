from collections import Counter


class ChargingEventSummaryService:
    def generate_summary(self, events):
        if not events:
            return (
                "Charging Event Summary\n"
                "======================\n\n"
                "No charging-related events detected.\n"
            )

        event_names = []

        for event in events:

            event_name = (
                event.get("description")
                or event.get("event")
                or "Unknown event"
            )

            event_names.append(
                event_name
            )

        unique_events = list(dict.fromkeys(event_names))
        counts = Counter(event_names)

        lines = [
            "Charging Event Summary",
            "======================",
            "",
            f"Total events detected: {len(events)}",
            f"Unique event types: {len(unique_events)}",
            "",
            "Detected Events:",
            ""
        ]

        for event_name in unique_events:
            lines.append(
                f"- {event_name} (Occurrences: {counts[event_name]})"
            )

        lines.extend(
            [
                "",
                "Overall Assessment:",
                self._generate_assessment(unique_events),
                ""
            ]
        )

        return "\n".join(lines)

    def _generate_assessment(self, event_names):
        assessment_parts = []

        if any(
            "permission denied" in event.lower()
            for event in event_names
        ):
            assessment_parts.append(
                "Charging permission was denied."
            )

        if any(
            "not ready" in event.lower()
            for event in event_names
        ):
            assessment_parts.append(
                "Vehicle charging readiness requirements were not met."
            )

        if any(
            "error state" in event.lower()
            for event in event_names
        ):
            assessment_parts.append(
                "Charging state machine entered an error state."
            )

        if any(
            "contactors" in event.lower()
            for event in event_names
        ):
            assessment_parts.append(
                "HV contactor status may have prevented charging."
            )

        if any(
            "not requested" in event.lower()
            for event in event_names
        ):
            assessment_parts.append(
                "Charging request was not successfully initiated."
            )

        if not assessment_parts:
            assessment_parts.append(
                "Charging-related events were detected and should be investigated."
            )

        return " ".join(assessment_parts)

    def save_summary(self, summary, output_path):
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(summary)

        return output_path