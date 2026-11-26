from collections import Counter


class AscChargingAnalysisService:
    SIGNAL_GROUPS = {
        "connector": ("HVLM_Steckerstatus_A", "HVLM_Steckerstatus_B"),
        "control_pilot_state": ("HVLM_CP_State_A", "HVLM_CP_State_B"),
        "control_pilot_current": ("HVLM_CP_MaxStrom_A", "HVLM_CP_MaxStrom_B"),
        "charging_request": ("HVLM_Ladevorgang_Anf",),
        "charging_workflow": ("HVLM_ZustandLadeablauf",),
        "heater_fault": ("KL_Fehler_HV_Heizer",),
        "v2l": ("HVLM_OBG_SollModus", "HVLE_OBG_IstModus", "HVLM_V2L_STDSollSpannung", "HVLM_V2X_SollFrequenz", "HVLX_V2X_IstModus"),
    }
    TARGET_SIGNALS = frozenset(
        signal
        for signals in SIGNAL_GROUPS.values()
        for signal in signals
    )
    VALUE_TRANSLATIONS = {
        "Stecker_steckt_und_verriegelt": "Charging connector inserted and locked",
        "Stecker_steckt_nicht_verriegelt": "Charging connector inserted but not locked",
        "kein_Stecker_erkannt": "No connector detected",
        "DC_Laden_Angefordert": "DC charging requested",
        "Laden_nicht_angefordert": "Charging not requested",
        "HVBatterie_Laden": "HV-battery charging active",
        "Laden_beenden": "Charging termination in progress",
        "Fehler": "Charging workflow error",
        "C2": "Established CP charging state, subtype C2",
        "B2": "Established CP connected state, subtype B2",
        "Init": "CP interface initialization state",
        "nicht_bekannt": "Value unknown",
        "Kein HV Fehler am HV Heizer erkannt": "No HV-heater fault detected",
    }

    def analyze(self, dbc_analysis: dict) -> dict:
        timelines = {signal: [] for signal in self.TARGET_SIGNALS}
        for sample in dbc_analysis.get("signal_samples") or []:
            signal_name = str(sample.get("signal_name", ""))
            if signal_name not in timelines:
                continue
            timestamp = self._timestamp(sample.get("timestamp"))
            if timestamp is None:
                continue
            value = self._value(sample.get("value"))
            timelines[signal_name].append(
                {
                    "timestamp": timestamp,
                    "value": value,
                    "value_translation": self._translate(value),
                    "channel": sample.get("channel"),
                    "arbitration_id": sample.get("arbitration_id"),
                    "message_name": sample.get("message_name"),
                }
            )
        signals = {
            signal_name: self._summarize_signal(samples)
            for signal_name, samples in timelines.items()
            if samples
        }
        progression = self._progression(signals)
        classification = self._classification(progression, signals)
        charging_workflow = self._charging_workflow_status(classification, progression)
        event_timeline = self._event_timeline(timelines)
        reference_timestamp = event_timeline[0]["timestamp"] if event_timeline else None
        heater_faults = self._heater_fault_analysis(timelines["KL_Fehler_HV_Heizer"])
        v2l = self._v2l_assessment(timelines)
        return {
            "source_file": dbc_analysis.get("source_file"),
            "classification": classification,
            "charging_progression": self._charging_progression(classification),
            "connector_recognition": progression["connector_recognition"],
            "control_pilot_recognition": progression["control_pilot_recognition"],
            "charging_request": progression["charging_request"],
            "charging_workflow": charging_workflow,
            "root_cause_status": "UNCONFIRMED",
            "reference_timestamp": reference_timestamp,
            "event_timeline": event_timeline,
            "target_signal_count": len(signals),
            "target_sample_count": sum(item["sample_count"] for item in signals.values()),
            "signals": signals,
            "signal_value_translations": dict(self.VALUE_TRANSLATIONS),
            "heater_fault_analysis": heater_faults,
            "v2l_assessment": v2l,
            "engineering_conclusion": self._conclusion(classification),
            "evidence_limitations": [
                "The analysis identifies observed charging progression and stopping stage from decoded ASC signals.",
                "Observed state agreement and event ordering do not by themselves establish the underlying physical root cause.",
            ],
        }

    def _v2l_assessment(self, timelines):
        names = self.SIGNAL_GROUPS["v2l"]
        rows = {name: sorted(timelines.get(name, []), key=lambda x: x["timestamp"]) for name in names}
        def is_reverse(value):
            value = str(value).casefold()
            return any(token in value for token in ("rueckspeis", "rückspeis", "reverse", "export"))
        def is_standby(value):
            return str(value).strip().casefold() in ("standby", "0", "inactive", "inaktiv")
        requested = any(is_reverse(x["value"]) for x in rows[names[0]])
        active = any(is_reverse(x["value"]) for x in rows[names[1]])
        if active:
            classification = "REVERSE_POWER_REPORTED_ACTIVE"
        elif requested:
            classification = "REVERSE_POWER_REQUESTED_NOT_CONFIRMED_ACTIVE"
        elif rows[names[0]] and rows[names[1]] and all(is_standby(x["value"]) for name in names[:2] for x in rows[name]):
            classification = "REVERSE_POWER_NOT_OBSERVED"
        else:
            classification = "INSUFFICIENT_EVIDENCE"
        details = {}
        for name in names:
            samples = rows[name]
            summary = self._summarize_signal(samples) if samples else {}
            details[name] = {
                "sample_count": len(samples),
                "first_timestamp": summary.get("first_timestamp"),
                "last_timestamp": summary.get("last_timestamp"),
                "unique_values": summary.get("unique_values", []),
                "transitions": summary.get("transitions", []),
            }
        return {
            "classification": classification,
            "reverse_power_requested": "OBSERVED" if requested else "NOT_OBSERVED" if rows[names[0]] else "NOT_DECODED",
            "reverse_power_active": "REPORTED" if active else "NOT_OBSERVED" if rows[names[1]] else "NOT_DECODED",
            "v2l_operation_confirmed": "NOT_CONFIRMED",
            "signals": details,
            "engineering_conclusion": {
                "REVERSE_POWER_REPORTED_ACTIVE": "Reverse operation was reported by the onboard charger; actual electrical power output is not independently confirmed.",
                "REVERSE_POWER_REQUESTED_NOT_CONFIRMED_ACTIVE": "Reverse operation was requested but was not confirmed active.",
                "REVERSE_POWER_NOT_OBSERVED": "Requested and actual onboard charger modes remained in Standby; reverse operation was not observed.",
                "INSUFFICIENT_EVIDENCE": "Decoded evidence is insufficient to determine reverse operation.",
            }[classification],
        }

    def _summarize_signal(self, samples: list[dict]) -> dict:
        ordered = sorted(samples, key=lambda item: item["timestamp"])
        transitions = []
        previous = object()
        values = []
        counts = Counter()
        for sample in ordered:
            value = sample["value"]
            counts[value] += 1
            if value not in values:
                values.append(value)
            if value != previous:
                transitions.append(sample)
                previous = value
        return {
            "sample_count": len(ordered),
            "first_timestamp": ordered[0]["timestamp"],
            "last_timestamp": ordered[-1]["timestamp"],
            "first_value": ordered[0]["value"],
            "first_value_translation": self._translate(ordered[0]["value"]),
            "last_value": ordered[-1]["value"],
            "last_value_translation": self._translate(ordered[-1]["value"]),
            "unique_values": values,
            "translated_values": {value: self._translate(value) for value in values},
            "value_counts": dict(counts),
            "transition_count": max(0, len(transitions) - 1),
            "transitions": transitions,
        }

    def _progression(self, signals: dict) -> dict:
        connector_values = self._values(signals, self.SIGNAL_GROUPS["connector"])
        cp_values = self._values(signals, self.SIGNAL_GROUPS["control_pilot_state"])
        request_values = self._values(signals, self.SIGNAL_GROUPS["charging_request"])
        workflow_values = self._values(signals, self.SIGNAL_GROUPS["charging_workflow"])
        connector_positive = self._contains_any(
            connector_values,
            ("stecker_steckt", "stecker_erkannt", "connected", "plugged"),
            exclusions=("kein_stecker", "nicht_erkannt"),
        )
        connector_negative = self._contains_any(
            connector_values,
            ("kein_stecker", "nicht_erkannt", "not detected", "unplugged"),
        )
        cp_established = self._contains_any(
            cp_values,
            ("b", "c", "d", "b1", "b2", "c1", "c2", "d1", "d2", "state b", "state c", "state d"),
        )
        cp_not_established = bool(cp_values) and not cp_established and self._contains_any(
            cp_values,
            ("a", "init", "kein_zustand", "state a"),
        )
        request_active = self._contains_any(
            request_values,
            ("dc_laden_angefordert", "laden_angefordert", "charging requested", "active"),
            exclusions=("nicht_angefordert", "not requested", "inactive"),
        )
        request_inactive = self._contains_any(
            request_values,
            ("nicht_angefordert", "not requested", "inactive"),
        )
        workflow_active = self._contains_any(
            workflow_values,
            ("hvbatterie_laden", "laden_aktiv", "charging_active", "active charging"),
        )
        workflow_terminating = self._contains_any(
            workflow_values,
            ("laden_beenden", "terminating", "termination"),
        )
        workflow_completed = self._contains_any(
            workflow_values,
            ("completed", "complete", "abgeschlossen", "beendet"),
        )
        workflow_error = self._contains_any(
            workflow_values,
            ("error", "fehler", "abbruch", "abort"),
        )
        prerequisites_not_met = self._contains_any(
            workflow_values,
            ("nicht_erfuellt", "not satisfied", "not ready"),
        )
        active_before_error = self._active_before_error(signals)
        return {
            "connector_recognition": "RECOGNIZED" if connector_positive else "NOT_RECOGNIZED" if connector_negative else "INDETERMINATE",
            "control_pilot_recognition": "ESTABLISHED" if cp_established else "NOT_ESTABLISHED" if cp_not_established else "INDETERMINATE",
            "charging_request": "OBSERVED" if request_active else "NOT_OBSERVED" if request_inactive else "INDETERMINATE",
            "charging_workflow": "COMPLETED" if workflow_completed else "ERROR" if workflow_error else "ACTIVE" if workflow_active else "TERMINATING" if workflow_terminating else "PREREQUISITES_NOT_MET" if prerequisites_not_met else "INDETERMINATE",
            "workflow_active": workflow_active,
            "workflow_terminating": workflow_terminating,
            "workflow_completed": workflow_completed,
            "workflow_error": workflow_error,
            "active_before_error": active_before_error,
            "prerequisites_not_met": prerequisites_not_met,
        }

    def _classification(self, progression: dict, signals: dict) -> str:
        if progression["workflow_completed"]:
            return "COMPLETED"
        if progression["workflow_error"] and progression["active_before_error"]:
            return "STARTED_THEN_INTERRUPTED"
        if progression["workflow_error"]:
            return "ERROR_BEFORE_START"
        if progression["workflow_active"]:
            return "ACTIVE"
        if progression["charging_request"] == "OBSERVED" and progression["prerequisites_not_met"]:
            return "REQUESTED_PREREQUISITES_NOT_MET"
        if progression["charging_request"] == "OBSERVED":
            return "REQUESTED_NOT_STARTED"
        if progression["connector_recognition"] == "NOT_RECOGNIZED" and progression["control_pilot_recognition"] == "NOT_ESTABLISHED":
            return "INTERFACE_NOT_ESTABLISHED"
        if progression["prerequisites_not_met"]:
            return "PREREQUISITES_NOT_MET"
        if progression["charging_request"] == "NOT_OBSERVED":
            return "NOT_REQUESTED"
        if not signals:
            return "INSUFFICIENT_EVIDENCE"
        return "UNDETERMINED"

    def _active_before_error(self, signals: dict) -> bool:
        workflow = signals.get("HVLM_ZustandLadeablauf", {})
        transitions = workflow.get("transitions", [])
        error_timestamps = [
            item["timestamp"]
            for item in transitions
            if self._matches(item["value"], ("fehler", "error", "abbruch", "abort"))
        ]
        if not error_timestamps:
            return False
        first_error = min(error_timestamps)
        return any(
            item["timestamp"] <= first_error
            and self._matches(item["value"], ("hvbatterie_laden", "laden_aktiv", "charging_active", "active charging"))
            for item in transitions
        )

    def _charging_workflow_status(self, classification: str, progression: dict) -> str:
        if classification == "STARTED_THEN_INTERRUPTED" and progression["workflow_error"]:
            return "ERROR_AFTER_ACTIVE_CHARGING"
        return progression["charging_workflow"]

    def _event_timeline(self, timelines: dict[str, list[dict]]) -> list[dict]:
        candidates = []
        for signal_name, samples in timelines.items():
            if signal_name == "KL_Fehler_HV_Heizer":
                continue
            ordered = sorted(samples, key=lambda item: item["timestamp"])
            previous_value = None
            for index, sample in enumerate(ordered):
                value = sample["value"]
                if index and value == previous_value:
                    continue
                if self._relevant_event(signal_name, value):
                    candidates.append(
                        {
                            "timestamp": sample["timestamp"],
                            "signal_name": signal_name,
                            "previous_value": previous_value,
                            "value": value,
                            "value_translation": self._translate(value),
                            "signal_transition": self._transition_text(signal_name, previous_value, value),
                            "engineering_meaning": self._engineering_meaning(signal_name, previous_value, value),
                            "channel": sample.get("channel"),
                            "arbitration_id": sample.get("arbitration_id"),
                            "message_name": sample.get("message_name"),
                        }
                    )
                previous_value = value
        candidates.sort(key=lambda item: (item["timestamp"], item["signal_name"]))
        if not candidates:
            return []
        reference_timestamp = candidates[0]["timestamp"]
        for item in candidates:
            item["relative_time_seconds"] = round(item["timestamp"] - reference_timestamp, 6)
            item["relative_time"] = f'+{item["relative_time_seconds"]:.3f} s'
        return candidates

    def _relevant_event(self, signal_name: str, value: str) -> bool:
        normalized = self._normalized(value)
        if signal_name in self.SIGNAL_GROUPS["connector"]:
            return self._matches(normalized, ("stecker", "connector", "plug"))
        if signal_name in self.SIGNAL_GROUPS["control_pilot_state"]:
            return self._matches(normalized, ("b1", "b2", "c1", "c2", "d1", "d2", "init", "state"))
        if signal_name in self.SIGNAL_GROUPS["control_pilot_current"]:
            return normalized not in {"nicht_bekannt", "unknown", "value unknown"}
        if signal_name in self.SIGNAL_GROUPS["charging_request"]:
            return self._matches(normalized, ("laden", "charging", "active", "inactive"))
        if signal_name in self.SIGNAL_GROUPS["charging_workflow"]:
            return self._matches(normalized, ("laden", "charging", "fehler", "error", "abbruch", "abort"))
        return False

    def _transition_text(self, signal_name: str, previous_value: str | None, value: str) -> str:
        if previous_value is None:
            return f"{signal_name} = {value}"
        return f"{previous_value} -> {value}"

    def _engineering_meaning(self, signal_name: str, previous_value: str | None, value: str) -> str:
        normalized = self._normalized(value)
        if signal_name in self.SIGNAL_GROUPS["connector"]:
            if "stecker_steckt_und_verriegelt" in normalized:
                return "Charging connector was inserted and locked."
            if "stecker_steckt_nicht_verriegelt" in normalized:
                return "Charging connector was inserted but not locked."
            if "kein_stecker" in normalized or "not detected" in normalized:
                return "No charging connector was detected."
        if signal_name in self.SIGNAL_GROUPS["control_pilot_state"]:
            if normalized == "c2":
                return "CP communication was established at a charging-capable state."
            if normalized == "b2":
                return "CP state moved to the established connected state B2."
            if normalized == "init":
                return "CP interface returned to initialization."
        if signal_name in self.SIGNAL_GROUPS["control_pilot_current"]:
            if self._numeric_zero(value):
                return "Available or advertised CP current ended at zero."
            return "Available or advertised CP current changed."
        if signal_name in self.SIGNAL_GROUPS["charging_request"]:
            if "nicht_angefordert" in normalized or "not requested" in normalized:
                return "DC charging request was withdrawn."
            if "angefordert" in normalized or "requested" in normalized:
                return "DC charging was requested."
        if signal_name in self.SIGNAL_GROUPS["charging_workflow"]:
            if "hvbatterie_laden" in normalized or "active charging" in normalized:
                return "HV-battery charging was active."
            if "laden_beenden" in normalized or "termination" in normalized:
                return "Charging termination began."
            if "fehler" in normalized or "error" in normalized:
                return "Charging workflow entered an error state."
        translation = self._translate(value)
        if translation != value:
            return translation + "."
        if previous_value is None:
            return "Relevant charging state was observed."
        return "Relevant charging state changed."

    def _heater_fault_analysis(self, samples: list[dict]) -> dict:
        ordered = sorted(samples, key=lambda item: item["timestamp"])
        intervals = []
        active_start = None
        for sample in ordered:
            active = self._heater_fault_active(sample["value"])
            if active and active_start is None:
                active_start = sample["timestamp"]
            elif not active and active_start is not None:
                intervals.append({"start_timestamp": active_start, "end_timestamp": sample["timestamp"]})
                active_start = None
        if active_start is not None:
            intervals.append({"start_timestamp": active_start, "end_timestamp": None})
        return {
            "sample_count": len(ordered),
            "fault_observed": bool(intervals),
            "fault_interval_count": len(intervals),
            "active_at_trace_end": bool(intervals and intervals[-1]["end_timestamp"] is None),
            "intervals": intervals,
            "charging_causal_status": "UNCONFIRMED",
        }

    def _charging_progression(self, classification: str) -> str:
        if classification == "COMPLETED":
            return "COMPLETED"
        if classification in {"ACTIVE", "STARTED_THEN_INTERRUPTED"}:
            return "OBSERVED"
        if classification == "INSUFFICIENT_EVIDENCE":
            return "INDETERMINATE"
        return "NOT_OBSERVED"

    def _conclusion(self, classification: str) -> str:
        conclusions = {
            "COMPLETED": "A completed charging sequence was observed in the ASC evidence.",
            "ACTIVE": "Active charging was observed, but completion was not established.",
            "STARTED_THEN_INTERRUPTED": "Charging was active in the captured interval, then transitioned through termination and entered an error state.",
            "ERROR_BEFORE_START": "The charging workflow entered an error state before active charging was established.",
            "REQUESTED_PREREQUISITES_NOT_MET": "Charging was requested, but charging prerequisites remained unsatisfied.",
            "REQUESTED_NOT_STARTED": "A charging request was observed, but active charging was not established.",
            "INTERFACE_NOT_ESTABLISHED": "The charging interface was not established and charging progression was not observed.",
            "PREREQUISITES_NOT_MET": "Charging remained in a prerequisite or standby condition.",
            "NOT_REQUESTED": "No active charging request was observed in the ASC evidence.",
            "INSUFFICIENT_EVIDENCE": "The ASC evidence is insufficient to classify charging progression.",
            "UNDETERMINED": "Charging evidence was observed, but the progression stage remains undetermined.",
        }
        return conclusions[classification]

    def _values(self, signals: dict, names: tuple[str, ...]) -> list[str]:
        return [self._normalized(value) for name in names for value in signals.get(name, {}).get("unique_values", [])]

    def _contains_any(self, values: list[str], tokens: tuple[str, ...], exclusions: tuple[str, ...] = ()) -> bool:
        return any(
            any(self._normalized(token) == value or self._normalized(token) in value for token in tokens)
            and not any(self._normalized(exclusion) in value for exclusion in exclusions)
            for value in values
        )

    def _matches(self, value: str, tokens: tuple[str, ...]) -> bool:
        normalized = self._normalized(value)
        return any(self._normalized(token) == normalized or self._normalized(token) in normalized for token in tokens)

    def _translate(self, value: str) -> str:
        normalized = self._normalized(value)
        for raw_value, translation in self.VALUE_TRANSLATIONS.items():
            if self._normalized(raw_value) == normalized:
                return translation
        return str(value)

    def _heater_fault_active(self, value: str) -> bool:
        normalized = self._normalized(value)
        if "kein hv fehler" in normalized or "no hv fault" in normalized:
            return False
        return normalized in {"fehler", "fault", "active", "1", "true"} or "fehler" in normalized or "fault" in normalized

    def _numeric_zero(self, value: str) -> bool:
        try:
            return float(str(value).strip().split()[0]) == 0.0
        except (TypeError, ValueError):
            return False

    def _normalized(self, value) -> str:
        return str(value).strip().lower()

    def _timestamp(self, value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _value(self, value) -> str:
        return str(value)
