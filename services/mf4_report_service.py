from pathlib import Path


class Mf4ReportService:
    def save_report(self, analysis: dict) -> Path:
        output_dir = self._output_dir()
        output_dir.mkdir(parents=True, exist_ok=True)
        analysis_path = output_dir / "mf4_analysis_report.txt"
        summary_path = output_dir / "mf4_case_summary.txt"
        report = self.generate_report(analysis)
        analysis_path.write_text(report, encoding="utf-8")
        summary_path.write_text(report, encoding="utf-8")
        return analysis_path

    def _output_dir(self) -> Path:
        return Path(__file__).resolve().parent.parent / "reports" / "mf4"

    def generate_report(self, analysis: dict) -> str:
        findings = analysis.get("findings", {})
        lines = [
            "MF4 Engineering Analysis",
            "=" * 80,
            "",
            f"MF4 Source: {Path(analysis.get('source_file', '')).name}",
            "",
            "Overall Engineering Assessment",
            "-" * 80,
            f"Charging progression: {analysis.get('charging_progression', 'INDETERMINATE')}",
            f"Connector recognition: {analysis.get('connector_recognition', 'INDETERMINATE')}",
            f"Control-pilot recognition: {analysis.get('control_pilot_recognition', 'INDETERMINATE')}",
            f"Explicit CP fault observed: {'YES' if analysis.get('cp_fault_observed') else 'NO'}",
            f"Root cause status: {analysis.get('root_cause_status', 'UNCONFIRMED')}",
            "",
            "Charging Prerequisite Assessment",
            "-" * 80,
        ]
        self._append_prerequisites(lines, findings)
        lines.extend(["", "Supporting MF4 Evidence", "-" * 80])
        self._append_evidence(lines, findings)
        lines.extend(["", "Duplicate Channel Observations", "-" * 80])
        self._append_duplicates(lines, analysis.get("duplicates", {}))
        lines.extend(["", "Timestamp Quality", "-" * 80])
        self._append_timestamp_quality(lines, findings)
        lines.extend(["", "Engineering Interpretation", "-" * 80])
        self._append_interpretation(lines, analysis)
        lines.extend(["", "Analysis Limitations", "-" * 80])
        self._append_limitations(lines)
        return "\n".join(lines) + "\n"

    def _append_prerequisites(self, lines, findings):
        self._append_state(lines, findings, "connector_a", "Connector path A")
        self._append_state(lines, findings, "connector_b", "Connector path B")
        self._append_state(lines, findings, "connector_sensor", "Connector sensor")
        self._append_state(lines, findings, "dc_plug_status", "DC connector status")
        self._append_state(lines, findings, "cp_state_a", "Control-pilot path A")
        self._append_state(lines, findings, "cp_state_b", "Control-pilot path B")
        self._append_state(lines, findings, "cp_status_a", "CP physical recognition")
        self._append_state(lines, findings, "cp_frequency_a", "CP frequency")
        self._append_state(lines, findings, "cp_duty_a", "CP duty cycle")
        self._append_state(lines, findings, "cp_max_current_a", "CP available current A")
        self._append_state(lines, findings, "cp_max_current_b", "CP available current B")
        self._append_state(lines, findings, "cp_protocol_a", "CP protocol A")
        self._append_state(lines, findings, "cp_protocol_b", "CP protocol B")
        self._append_state(lines, findings, "vehicle_charge_capable", "General vehicle charging capability")
        self._append_state(lines, findings, "vehicle_ready_cdo", "CDO charging readiness")
        self._append_state(lines, findings, "vehicle_ready_cj", "CJ charging readiness")
        self._append_state(lines, findings, "vehicle_ready_plc", "PLC charging readiness")
        self._append_state(lines, findings, "charge_request", "Charging request")
        self._append_state(lines, findings, "active_charge_type", "Active charging mode")
        self._append_state(lines, findings, "bms_charging_active", "BMS charging state")

    def _append_state(self, lines, findings, key, label):
        entry = findings.get(key)
        if not entry:
            lines.append(f"{label}: NOT OBSERVED")
            return
        values = ", ".join(entry.get("unique_values", [])) or "NO VALUE"
        lines.append(f"{label}: {values}")

    def _append_evidence(self, lines, findings):
        ordered_keys = (
            "connector_a",
            "connector_b",
            "connector_sensor",
            "dc_plug_status",
            "cp_state_a",
            "cp_state_b",
            "cp_status_a",
            "cp_fault_a",
            "cp_fault_b",
            "cp_frequency_a",
            "cp_duty_a",
            "cp_max_current_a",
            "cp_max_current_b",
            "vehicle_charge_capable",
            "vehicle_ready_cdo",
            "vehicle_ready_cj",
            "vehicle_ready_plc",
            "charge_request",
            "active_charge_type",
            "bms_charging_active",
        )
        for key in ordered_keys:
            entry = findings.get(key)
            if not entry:
                continue
            lines.append(
                f"{entry['name']} | group={entry['group']} | index={entry['index']} | "
                f"samples={entry['samples']} | transitions={entry['transitions']} | "
                f"first={entry['first_value']} | last={entry['last_value']}"
            )

    def _append_duplicates(self, lines, duplicates):
        if not duplicates:
            lines.append("No duplicate occurrences were retained for the selected report signals.")
            return
        for name, entries in sorted(duplicates.items()):
            lines.append(f"{name}: {len(entries)} occurrences retained")
            for entry in entries:
                values = ", ".join(entry.get("unique_values", [])) or "NO VALUE"
                lines.append(
                    f"  group={entry['group']}, index={entry['index']}, "
                    f"samples={entry['samples']}, values={values}"
                )

    def _append_timestamp_quality(self, lines, findings):
        affected = [
            entry
            for entry in findings.values()
            if entry.get("invalid_timestamp_count", 0) > 0
        ]
        lines.append(f"Selected channels with filtered invalid timestamps: {len(affected)}")
        for entry in affected:
            lines.append(
                f"{entry['name']} | filtered={entry['invalid_timestamp_count']} | "
                f"valid_range={entry['valid_first_timestamp']} -> {entry['valid_last_timestamp']}"
            )

    def _append_interpretation(self, lines, analysis):
        if (
            analysis.get("charging_progression") == "NOT_OBSERVED"
            and analysis.get("connector_recognition") == "NOT_RECOGNIZED"
            and analysis.get("control_pilot_recognition") == "NOT_ESTABLISHED"
        ):
            lines.append("Charging did not become active during the MF4 recording.")
            lines.append("Multiple MF4 sources independently show that no charging connector was recognized and a valid control-pilot charging state was not established.")
            lines.append("No explicit control-pilot fault was observed in the selected MF4 evidence.")
            lines.append("The evidence localizes the missing prerequisite to connector/control-pilot recognition, but it does not establish the underlying physical cause.")
        else:
            lines.append("Charging prerequisite interpretation remains INDETERMINATE from the selected MF4 evidence.")
        lines.append(f"Root cause remains {analysis.get('root_cause_status', 'UNCONFIRMED').lower()}.")

    def _append_limitations(self, lines):
        lines.append("MF4 findings are limited to the explicitly selected and validated measurement channels.")
        lines.append("Duplicate channel names are preserved with group/index provenance and are not silently merged.")
        lines.append("Obviously invalid large MF4 timestamps are excluded from usable timestamp ranges but retained as a data-quality observation.")
        lines.append("This MF4 report is trace-local and does not use BLF, DLT, or PCAP findings to classify MF4 states.")
        lines.append("Absence of connector/control-pilot recognition does not establish whether no connector was physically present or whether a present connector, cable, EVSE, inlet, or detection circuit was not recognized.")
