from bisect import bisect_right


class BlfChargingFaultCorrelationService:

    def correlate(
        self,
        fault_signal: str,
        fault_samples: list[dict],
        charging_samples: dict[str, list[dict]],
        abnormal_values: set[str] | None = None,
        normal_values: set[str] | None = None,
    ) -> dict:
        abnormal_values = abnormal_values or {"Fehler"}
        normal_values = normal_values or {
            "Kein HV Fehler am HV Heizer erkannt",
            "Kein HV Fehler am EKK erkannt",
        }

        samples = sorted(fault_samples, key=lambda sample: sample["timestamp"])
        intervals = self._fault_intervals(samples, abnormal_values, normal_values)
        normalized_charging = {
            signal: sorted(values, key=lambda sample: sample["timestamp"])
            for signal, values in charging_samples.items()
        }

        correlated = []
        for interval in intervals:
            start = interval["start_timestamp"]
            end = interval["end_timestamp"]
            charging_state = {}

            for signal, values in normalized_charging.items():
                start_value = self._value_at(values, start)
                end_value = self._value_at(values, end) if end is not None else self._last_value(values)
                changed_during = self._changes_between(values, start, end)
                charging_state[signal] = {
                    "value_at_fault_start": start_value,
                    "value_at_fault_end": end_value,
                    "changes_during_fault": changed_during,
                }

            correlated.append(
                {
                    **interval,
                    "charging_state": charging_state,
                    "charging_state_changed_during_fault": any(
                        state["changes_during_fault"]
                        for state in charging_state.values()
                    ),
                    "charging_progressed_during_fault": self._charging_progressed(
                        charging_state
                    ),
                }
            )

        return {
            "fault_signal": fault_signal,
            "fault_intervals": correlated,
            "fault_interval_count": len(correlated),
            "recovered_interval_count": sum(
                interval["recovered"] for interval in correlated
            ),
            "persistent_at_end": bool(correlated and not correlated[-1]["recovered"]),
        }

    def _charging_progressed(self, charging_state: dict) -> bool:
        request = charging_state.get("HVLM_Ladevorgang_Anf", {})
        sequence = charging_state.get("HVLM_ZustandLadeablauf", {})
        request_values = (
            self._normalized_value(request.get("value_at_fault_start")),
            self._normalized_value(request.get("value_at_fault_end")),
        )
        sequence_values = (
            self._normalized_value(sequence.get("value_at_fault_start")),
            self._normalized_value(sequence.get("value_at_fault_end")),
        )
        return any(
            value not in (None, "Laden_nicht_angefordert")
            for value in request_values
        ) or any(
            value not in (None, "Stby_Ladevorbed_nicht_erfuellt")
            for value in sequence_values
        )

    def _normalized_value(self, value):
        if value is None:
            return None
        return str(value)

    def _fault_intervals(
        self,
        samples: list[dict],
        abnormal_values: set[str],
        normal_values: set[str],
    ) -> list[dict]:
        intervals = []
        active = None

        for sample in samples:
            value = str(sample["value"])
            timestamp = sample["timestamp"]

            if value in abnormal_values:
                if active is None:
                    active = {
                        "start_timestamp": timestamp,
                        "start_value": value,
                        "abnormal_samples": 1,
                    }
                else:
                    active["abnormal_samples"] += 1
                continue

            if active is None:
                continue

            if value in normal_values:
                intervals.append(
                    {
                        **active,
                        "end_timestamp": timestamp,
                        "end_value": value,
                        "duration_seconds": timestamp - active["start_timestamp"],
                        "recovered": True,
                    }
                )
                active = None

        if active is not None:
            intervals.append(
                {
                    **active,
                    "end_timestamp": None,
                    "end_value": None,
                    "duration_seconds": None,
                    "recovered": False,
                }
            )

        return intervals

    def _value_at(self, samples: list[dict], timestamp):
        if not samples:
            return None
        timestamps = [sample["timestamp"] for sample in samples]
        index = bisect_right(timestamps, timestamp) - 1
        if index < 0:
            return None
        return samples[index]["value"]

    def _last_value(self, samples: list[dict]):
        return samples[-1]["value"] if samples else None

    def _changes_between(self, samples: list[dict], start, end) -> int:
        if not samples:
            return 0
        selected = [
            sample
            for sample in samples
            if sample["timestamp"] >= start
            and (end is None or sample["timestamp"] <= end)
        ]
        if len(selected) < 2:
            return 0
        changes = 0
        previous = selected[0]["value"]
        for sample in selected[1:]:
            current = sample["value"]
            if current != previous:
                changes += 1
                previous = current
        return changes
