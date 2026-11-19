from collections import Counter


class ChargingEventSummaryService:
    def generate_summary(self, events):
        if not events:
            return "\n".join([
                "CHARGING EVENT SUMMARY",
                "=" * 80,
                "",
                "SUMMARY",
                "-" * 80,
                "Charging observations:       0",
                "Distinct conditions:         0",
                "",
                "ENGINEERING ASSESSMENT",
                "-" * 80,
                "No charging-related observations were detected.",
                "",
            ])

        event_names = [self._event_name(event) for event in events]
        unique_events = list(dict.fromkeys(event_names))
        counts = Counter(event_names)
        grouped_events = {name: [] for name in unique_events}

        for event, event_name in zip(events, event_names):
            grouped_events[event_name].append(event)

        lines = [
            "CHARGING EVENT SUMMARY",
            "=" * 80,
            "",
            "SUMMARY",
            "-" * 80,
            f"Charging observations:       {len(events)}",
            f"Distinct conditions:         {len(unique_events)}",
            "",
            "OBSERVED CONDITIONS",
            "-" * 80,
        ]

        for index, event_name in enumerate(unique_events):
            representative = grouped_events[event_name][0]
            lines.extend([
                event_name,
                f"  Signal: {representative.get('signal', 'Unknown')}",
                f"  Raw value: {representative.get('value', 'Unknown')}",
                f"  Observations: {counts[event_name]}",
            ])
            if index < len(unique_events) - 1:
                lines.append("")

        lines.extend([
            "",
            "ENGINEERING ASSESSMENT",
            "-" * 80,
            self._generate_assessment(unique_events),
            "",
        ])
        return "\n".join(lines)

    def _event_name(self, event):
        return event.get("description") or event.get("event") or "Unknown condition"

    def _generate_assessment(self, event_names):
        normalized = [event.lower() for event in event_names]
        assessments = []

        if any("permission denied" in event for event in normalized):
            assessments.append("Charging permission denial was observed.")
        if any("not ready" in event or "readiness" in event for event in normalized):
            assessments.append("Charging readiness requirements were not met.")
        if any("error state" in event or "charging error" in event for event in normalized):
            assessments.append("The charging workflow entered an error state.")
        if any("contactor" in event for event in normalized):
            assessments.append("An HV contactor-related charging condition was observed.")
        if any("not requested" in event for event in normalized):
            assessments.append('No transition from "charging not requested" to an active charging request was observed during the analyzed trace.')
        if any("completed" in event or "charging complete" in event for event in normalized):
            assessments.append("A charging-completion condition was observed.")
        if any("charging active" in event or "charging started" in event for event in normalized):
            assessments.append("An active charging condition was observed.")

        if not assessments:
            assessments.append("Charging-related conditions were observed; their diagnostic significance depends on the supporting signal timeline.")

        return " ".join(assessments)

    def save_summary(self, summary, output_path):
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(summary)
        return output_path
