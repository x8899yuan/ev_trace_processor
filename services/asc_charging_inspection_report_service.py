from pathlib import Path


class AscChargingInspectionReportService:
    SIGNAL_ORDER = (
        "HVLM_Steckerstatus_A",
        "HVLM_Steckerstatus_B",
        "HVLM_CP_State_A",
        "HVLM_CP_State_B",
        "HVLM_CP_MaxStrom_A",
        "HVLM_CP_MaxStrom_B",
        "HVLM_Ladevorgang_Anf",
        "HVLM_ZustandLadeablauf",
        "KL_Fehler_HV_Heizer",
    )

    def generate(self, analysis: dict, output_path: Path) -> Path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "ASC CHARGING INSPECTION REPORT",
            "=" * 120,
            "",
            "SOURCE",
            "-" * 120,
            f"ASC file: {analysis.get('source_file', 'source not supplied')}",
            "",
            "CHARGING ASSESSMENT",
            "-" * 120,
            f"Classification: {analysis.get('classification', 'UNDETERMINED')}",
            f"Charging progression: {analysis.get('charging_progression', 'INDETERMINATE')}",
            f"Connector recognition: {analysis.get('connector_recognition', 'INDETERMINATE')}",
            f"Control-pilot recognition: {analysis.get('control_pilot_recognition', 'INDETERMINATE')}",
            f"Charging request: {analysis.get('charging_request', 'INDETERMINATE')}",
            f"Charging workflow: {analysis.get('charging_workflow', 'INDETERMINATE')}",
            f"Root cause status: {analysis.get('root_cause_status', 'UNCONFIRMED')}",
            f"Target signals observed: {analysis.get('target_signal_count', 0)}",
            f"Target signal samples: {analysis.get('target_sample_count', 0)}",
            "",
            "ENGINEERING CONCLUSION",
            "-" * 120,
            str(analysis.get("engineering_conclusion", "No evidence-supported conclusion available.")),
            "",
            "CHARGING EVENT TIMELINE",
            "-" * 120,
        ]
        timeline = analysis.get("event_timeline") or []
        if timeline:
            lines.append(f"Reference timestamp: {self._time(analysis.get('reference_timestamp'))} (+0.000 s)")
            lines.append("")
            lines.append("ASC timestamp | Relative time | Signal transition | Engineering meaning")
            lines.append("-" * 120)
            for event in timeline:
                lines.append(
                    f"{self._time(event.get('timestamp'))} | "
                    f"{event.get('relative_time', 'Unknown')} | "
                    f"{event.get('signal_transition', 'Unknown')} | "
                    f"{event.get('engineering_meaning', 'No engineering interpretation available.')}"
                )
        else:
            lines.append("No charging-event timeline could be derived from the decoded ASC evidence.")
        lines.extend([
            "",
            "SIGNAL TIMELINES",
            "-" * 120,
        ])
        signals = analysis.get("signals") or {}
        observed_names = [name for name in self.SIGNAL_ORDER if name in signals]
        if not observed_names:
            lines.append("No targeted charging signals were observed.")
        for index, name in enumerate(observed_names):
            signal = signals[name]
            lines.extend([
                name,
                f"  Samples: {signal.get('sample_count', 0)}",
                f"  First timestamp: {self._time(signal.get('first_timestamp'))}",
                f"  Last timestamp: {self._time(signal.get('last_timestamp'))}",
                f"  First value: {self._translated_value(signal.get('first_value'), signal.get('first_value_translation'))}",
                f"  Last value: {self._translated_value(signal.get('last_value'), signal.get('last_value_translation'))}",
                f"  Unique values: {self._translated_values(signal)}",
                f"  State transitions: {signal.get('transition_count', 0)}",
            ])
            transitions = signal.get("transitions") or []
            for transition in transitions[:20]:
                lines.append(
                    "    "
                    f"{self._time(transition.get('timestamp'))} | "
                    f"{self._translated_value(transition.get('value'), transition.get('value_translation'))} | "
                    f"channel={transition.get('channel', 'Unknown')} | "
                    f"can_id={self._can_id(transition.get('arbitration_id'))} | "
                    f"message={transition.get('message_name', 'Unknown')}"
                )
            if len(transitions) > 20:
                lines.append(f"    ... {len(transitions) - 20} additional transitions omitted")
            if index < len(observed_names) - 1:
                lines.append("")
        heater = analysis.get("heater_fault_analysis") or {}
        lines.extend([
            "",
            "HV HEATER FAULT CORRELATION",
            "-" * 120,
            f"Heater samples: {heater.get('sample_count', 0)}",
            f"Fault observed: {'YES' if heater.get('fault_observed') else 'NO'}",
            f"Fault intervals: {heater.get('fault_interval_count', 0)}",
            f"Fault active at trace end: {'YES' if heater.get('active_at_trace_end') else 'NO'}",
            f"Charging causal status: {heater.get('charging_causal_status', 'UNCONFIRMED')}",
        ])
        for index, interval in enumerate(heater.get("intervals") or [], start=1):
            lines.append(
                f"Interval {index}: {self._time(interval.get('start_timestamp'))} -> "
                f"{self._time(interval.get('end_timestamp')) if interval.get('end_timestamp') is not None else 'trace end'}"
            )
        lines.extend([
            "",
            "EVIDENCE LIMITATIONS",
            "-" * 120,
            *[str(value) for value in analysis.get("evidence_limitations") or ["No evidence limitations supplied."]],
            "",
        ])
        output.write_text("\n".join(lines), encoding="utf-8")
        return output

    def _translated_value(self, value, translation=None) -> str:
        raw = "Unknown" if value is None else str(value)
        translated = raw if translation is None else str(translation)
        if translated == raw:
            return raw
        return f"{raw} ({translated})"

    def _translated_values(self, signal: dict) -> str:
        values = signal.get("unique_values") or []
        translations = signal.get("translated_values") or {}
        if not values:
            return "None"
        rendered = [self._translated_value(value, translations.get(value)) for value in values[:20]]
        if len(values) > 20:
            rendered.append(f"... (+{len(values) - 20})")
        return ", ".join(rendered)

    def _time(self, value) -> str:
        try:
            return f"{float(value):.6f}"
        except (TypeError, ValueError):
            return "Unknown"

    def _can_id(self, value) -> str:
        try:
            return f"0x{int(value):X}"
        except (TypeError, ValueError):
            return "Unknown"
