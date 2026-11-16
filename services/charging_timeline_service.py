class ChargingTimelineService:

    def build_timeline(
        self,
        signal_samples: dict[str, list[dict]],
    ) -> list[dict]:

        timeline: list[dict] = []

        for signal_name, samples in signal_samples.items():
            previous_value = None
            first_sample = True

            for sample in samples:
                current_value = sample["value"]

                if first_sample:
                    timeline.append(
                        {
                            "timestamp": sample["timestamp"],
                            "signal": signal_name,
                            "old_value": None,
                            "new_value": current_value,
                            "event_type": "INITIAL_STATE",
                        }
                    )
                    previous_value = current_value
                    first_sample = False
                    continue

                if current_value == previous_value:
                    continue

                timeline.append(
                    {
                        "timestamp": sample["timestamp"],
                        "signal": signal_name,
                        "old_value": previous_value,
                        "new_value": current_value,
                        "event_type": "TRANSITION",
                    }
                )
                previous_value = current_value

        timeline.sort(key=lambda event: event["timestamp"])
        return timeline
