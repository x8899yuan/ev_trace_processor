from collections import defaultdict


class BlfSignalAnomalyService:

    SIGNAL_KEYWORDS = (
        "error",
        "fault",
        "failure",
        "warn",
        "invalid",
        "timeout",
        "degrad",
        "shutdown",
        "overvoltage",
        "undervoltage",
        "overtemperature",
        "isolation",
        "interlock",
        "crash",
        "fehler",
        "stoer",
        "storung",
    )

    NORMAL_VALUE_KEYWORDS = (
        "no_error",
        "no error",
        "no_fault",
        "no fault",
        "not_active",
        "inactive",
        "normal",
        "fehlerfrei",
        "kein_fehler",
        "keinfehler",
        "kein hv fehler",
        "kein_kd_fehler",
        "kein_sammelfehler",
        "keine_stoerung",
        "keine_störung",
        "keine_warnung",
        "keine_vorwarnung",
        "keine_anforderung_warnlampe",
        "nicht_aktiv",
        "inaktiv",
    )

    UNAVAILABLE_VALUE_KEYWORDS = (
        "not_available",
        "not available",
        "unavailable",
        "sna",
        "reserved",
        "unknown",
        "ungueltig",
        "ungültig",
    )

    ABNORMAL_VALUE_KEYWORDS = (
        "active",
        "aktiv",
        "error",
        "fault",
        "failure",
        "failed",
        "warning",
        "warn",
        "invalid",
        "timeout",
        "degraded",
        "shutdown",
        "overvoltage",
        "undervoltage",
        "overtemperature",
        "isolation_fault",
        "interlock_open",
        "crash",
        "fehler",
        "stoerung",
        "störung",
        "nicht_ok",
        "not_ok",
    )

    def analyze(self, decoded_messages: list) -> dict:
        observations = defaultdict(list)

        for message in decoded_messages:
            timestamp = getattr(message, "timestamp", None)
            channel = getattr(message, "channel", None)
            arbitration_id = self._arbitration_id(message)
            message_name = getattr(message, "message_name", None)

            for signal_name, value in getattr(message, "signals", {}).items():
                if not self._is_candidate_signal(signal_name):
                    continue

                observations[signal_name].append(
                    {
                        "timestamp": timestamp,
                        "value": value,
                        "classification": self.classify_value(value),
                        "channel": channel,
                        "arbitration_id": arbitration_id,
                        "message_name": message_name,
                    }
                )

        findings = []

        for signal_name, samples in observations.items():
            abnormal_samples = [
                sample
                for sample in samples
                if sample["classification"] in {"ABNORMAL", "UNAVAILABLE"}
            ]
            if not abnormal_samples:
                continue

            classifications = {
                sample["classification"] for sample in abnormal_samples
            }
            first = abnormal_samples[0]
            last = abnormal_samples[-1]
            value_counts = self._value_counts(samples)

            findings.append(
                {
                    "signal": signal_name,
                    "severity": (
                        "WARNING"
                        if classifications == {"UNAVAILABLE"}
                        else "FAULT"
                    ),
                    "first_timestamp": first["timestamp"],
                    "last_timestamp": last["timestamp"],
                    "occurrences": len(abnormal_samples),
                    "first_value": first["value"],
                    "last_value": last["value"],
                    "recovered": self._recovered(samples),
                    "transitions": self._transitions(samples),
                    "value_counts": value_counts,
                    "channel": first["channel"],
                    "arbitration_id": first["arbitration_id"],
                    "message_name": first["message_name"],
                }
            )

        findings.sort(
            key=lambda finding: (
                0 if finding["severity"] == "FAULT" else 1,
                -finding["occurrences"],
                finding["signal"],
            )
        )

        return {
            "candidate_signals": len(observations),
            "findings": findings,
            "fault_count": sum(
                finding["severity"] == "FAULT" for finding in findings
            ),
            "warning_count": sum(
                finding["severity"] == "WARNING" for finding in findings
            ),
        }

    def classify_value(self, value) -> str:
        if value is None:
            return "UNAVAILABLE"
        if isinstance(value, bool):
            return "ABNORMAL" if value else "NORMAL"
        if isinstance(value, (int, float)):
            return "ABNORMAL" if value != 0 else "NORMAL"

        normalized = str(value).strip().lower().replace("-", "_")

        if any(keyword in normalized for keyword in self.NORMAL_VALUE_KEYWORDS):
            return "NORMAL"
        if any(
            keyword in normalized for keyword in self.UNAVAILABLE_VALUE_KEYWORDS
        ):
            return "UNAVAILABLE"
        if any(keyword in normalized for keyword in self.ABNORMAL_VALUE_KEYWORDS):
            return "ABNORMAL"
        return "INDETERMINATE"

    def _is_candidate_signal(self, signal_name: str) -> bool:
        normalized = signal_name.lower()
        return any(keyword in normalized for keyword in self.SIGNAL_KEYWORDS)

    def _arbitration_id(self, message):
        for attribute in ("arbitration_id", "can_id", "frame_id"):
            value = getattr(message, attribute, None)
            if value is not None:
                return value
        return None

    def _transitions(self, samples: list[dict]) -> list[dict]:
        transitions = []
        previous = None
        first = True

        for sample in samples:
            current = sample["value"]
            if first:
                previous = current
                first = False
                continue
            if current == previous:
                continue
            transitions.append(
                {
                    "timestamp": sample["timestamp"],
                    "old_value": previous,
                    "new_value": current,
                }
            )
            previous = current

        return transitions

    def _recovered(self, samples: list[dict]) -> bool:
        abnormal_seen = False

        for sample in samples:
            classification = sample["classification"]
            if classification in {"ABNORMAL", "UNAVAILABLE"}:
                abnormal_seen = True
            elif abnormal_seen and classification == "NORMAL":
                return True

        return False

    def _value_counts(self, samples: list[dict]) -> dict[str, int]:
        counts = defaultdict(int)
        for sample in samples:
            counts[str(sample["value"])] += 1
        return dict(sorted(counts.items()))
