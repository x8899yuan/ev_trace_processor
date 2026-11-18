from pathlib import Path
from services.engineering_value_formatter import EngineeringValueFormatter


class BlfVehicleInventoryReportService:
    def save_report(
        self,
        inventory,
        file_stem: str,
        blf_inventory=None,
        statistics=None,
        charging_analysis: dict | None = None,
        anomaly_analysis: dict | None = None,
        charging_fault_correlation: dict | None = None,
    ) -> Path:
        output_dir = self._output_dir()
        output_dir.mkdir(parents=True, exist_ok=True)
        analysis_path = output_dir / "blf_analysis_report.txt"
        summary_path = output_dir / "blf_case_summary.txt"
        analysis_report = self._generate_report(
            inventory,
            file_stem,
            blf_inventory,
            statistics,
            charging_analysis,
            anomaly_analysis,
            charging_fault_correlation,
        )
        case_summary = self._generate_case_summary(
            inventory,
            file_stem,
            charging_analysis,
            anomaly_analysis,
            charging_fault_correlation,
        )
        analysis_path.write_text(analysis_report, encoding="utf-8")
        summary_path.write_text(case_summary, encoding="utf-8")
        return analysis_path

    def _output_dir(self) -> Path:
        return Path(__file__).resolve().parent.parent / "reports" / "blf"

    def _generate_case_summary(self, inventory, file_stem: str, charging_analysis: dict | None, anomaly_analysis: dict | None, charging_fault_correlation: dict | None) -> str:
        lines = ["BLF CASE SUMMARY", "=" * 80, "", f"VIN: {self._vin(inventory)}", f"VIN Status: {self._vin_status(inventory)}", "VIN Source: VIN_01 CAN/DBC evidence reconstructed from the BLF trace.", f"BLF Source: {Path(file_stem).name}", "", "Overall Engineering Assessment", "-" * 80]
        self._append_overall(lines, charging_analysis, anomaly_analysis)
        self._append_primary_fault_summary(lines, anomaly_analysis)
        lines.extend(["", "Charging Assessment", "-" * 80])
        self._append_interpretation(lines, charging_analysis)
        lines.extend(["", "Charging Prerequisite Assessment", "-" * 80])
        self._append_charging_prerequisites(lines, charging_analysis)
        lines.extend(["", "Charging-to-Fault Correlation", "-" * 80])
        self._append_correlation(lines, charging_fault_correlation)
        lines.extend(["", "Vehicle / ECU Inventory", "-" * 80])
        self._append_inventory(lines, inventory)
        lines.extend(["", "Analysis Limitations", "-" * 80])
        self._append_limitations(lines, charging_analysis, anomaly_analysis, charging_fault_correlation)
        return "\n".join(lines) + "\n"

    def _generate_report(self, inventory, file_stem: str, blf_inventory, statistics, charging_analysis: dict | None, anomaly_analysis: dict | None, charging_fault_correlation: dict | None) -> str:
        lines = ["BLF Engineering Analysis", "=" * 80, "", f"VIN: {self._vin(inventory)}", f"VIN Status: {self._vin_status(inventory)}", "VIN Source: VIN_01 CAN/DBC evidence reconstructed from the BLF trace.", f"BLF Source: {Path(file_stem).name}", "", "Overall Engineering Assessment", "-" * 80]
        self._append_overall(lines, charging_analysis, anomaly_analysis)
        self._append_primary_fault_summary(lines, anomaly_analysis)
        lines.extend(["", "Charging Assessment", "-" * 80])
        self._append_charging(lines, charging_analysis)
        lines.extend(["", "Detailed Charging Timeline", "-" * 80])
        self._append_timeline(lines, charging_analysis)
        lines.extend(["", "Engineering Interpretation", "-" * 80])
        self._append_interpretation(lines, charging_analysis)
        lines.extend(["", "Charging Prerequisite Assessment", "-" * 80])
        self._append_charging_prerequisites(lines, charging_analysis)
        lines.extend(["", "Vehicle Signal Faults / Anomalies", "-" * 80])
        self._append_anomalies(lines, anomaly_analysis)
        lines.extend(["", "Charging-to-Fault Correlation", "-" * 80])
        self._append_correlation(lines, charging_fault_correlation)
        lines.extend(["", "Vehicle / ECU Inventory", "-" * 80])
        self._append_inventory(lines, inventory)
        lines.extend(["", "CAN Traffic Inventory", "-" * 80])
        self._append_can_inventory(lines, blf_inventory, statistics)
        lines.extend(["", "Analysis Limitations", "-" * 80])
        self._append_limitations(lines, charging_analysis, anomaly_analysis, charging_fault_correlation)
        return "\n".join(lines) + "\n"

    def _append_overall(self, lines, charging_analysis, anomaly_analysis):
        if charging_analysis and charging_analysis.get("available_signals"):
            lines.append("Charging-related signal evidence: OBSERVED")
            lines.append("Charging progression: NOT OBSERVED")
        else:
            lines.append("Charging-related signal evidence: NOT ANALYZED")
        if anomaly_analysis and anomaly_analysis.get("findings"):
            faults = anomaly_analysis.get("fault_count", 0)
            warnings = anomaly_analysis.get("warning_count", 0)
            lines.append(f"Vehicle signal anomalies: OBSERVED ({faults} fault, {warnings} warning)")
        else:
            lines.append("Vehicle signal anomalies: NOT ANALYZED")

    def _append_primary_fault_summary(self, lines, anomaly_analysis):
        if not anomaly_analysis:
            return
        summary = anomaly_analysis.get("primary_fault_summary")
        if not summary:
            return
        lines.extend([
            f"Primary fault signal: {summary['signal_name']}",
            f"Observed fault value: {summary['fault_value']}",
            f"Fault intervals: {summary['fault_intervals']}",
            f"Recovered intervals: {summary['recoveries']}",
            f"Active at trace end: {'YES' if summary['active_at_trace_end'] else 'NO'}",
            f"Charging causal status: {summary['charging_causal_status']}",
        ])

    def _append_charging(self, lines, charging_analysis):
        if not charging_analysis:
            lines.append("Charging analysis was not supplied for this report generation.")
            return
        target_ids = charging_analysis.get("target_can_ids", [])
        if target_ids:
            lines.append("Target CAN IDs: " + ", ".join(f"0x{value:X}" for value in target_ids))
        if charging_analysis.get("matched_frames") is not None:
            lines.append(f"Matched charging frames: {charging_analysis['matched_frames']:,}")
        values = charging_analysis.get("signal_values", {})
        available = charging_analysis.get("available_signals", [])
        unavailable = charging_analysis.get("unavailable_signals", [])
        lines.append(f"Available charging signals: {len(available)}")
        for signal in available:
            lines.append(f"{signal}: {values.get(signal, 'Not observed')}")
        lines.append(f"Unavailable target charging signals: {len(unavailable)}")
        for signal in unavailable:
            lines.append(f"{signal}: NOT OBSERVED")

    def _append_timeline(self, lines, charging_analysis):
        if not charging_analysis:
            lines.append("Timeline: NOT ANALYZED")
            return
        timeline = charging_analysis.get("timeline", [])
        if not timeline:
            lines.append("Timeline: NO DECODED CHARGING EVENTS")
            return
        for entry in timeline:
            timestamp = self._format_timestamp(entry.get("timestamp"))
            if entry.get("event_type") == "INITIAL_STATE":
                lines.append(f"{timestamp} | INITIAL_STATE | {entry.get('signal')} = {entry.get('new_value')}")
            else:
                lines.append(f"{timestamp} | TRANSITION | {entry.get('signal')}: {entry.get('old_value')} -> {entry.get('new_value')}")
        lines.append(f"Observed transitions: {charging_analysis.get('transition_entries', 0)}")

    def _append_interpretation(self, lines, charging_analysis):
        if not charging_analysis:
            lines.append("Charging conclusion: INDETERMINATE")
            return
        values = charging_analysis.get("signal_values", {})
        if values.get("HVLM_Ladevorgang_Anf") == "Laden_nicht_angefordert":
            lines.append("Charging request progression: NOT OBSERVED")
        else:
            lines.append("Charging request progression: INDETERMINATE")
        if values.get("HVLM_ZustandLadeablauf") == "Stby_Ladevorbed_nicht_erfuellt":
            lines.append("Charging sequence remained in the observed standby state with charging prerequisites not fulfilled.")
        if charging_analysis.get("transition_entries", 0) == 0 and charging_analysis.get("available_signals"):
            lines.append("No state transition was observed in the available targeted charging signals.")
        lines.append("The prerequisite-focused BLF evidence localizes the missing charging condition to connector/control-pilot recognition, while the underlying physical cause remains unconfirmed.")

    def _append_charging_prerequisites(self, lines, charging_analysis):
        if not charging_analysis:
            lines.append("Charging prerequisite assessment: NOT ANALYZED")
            return
        values = charging_analysis.get("signal_values", {})
        state = values.get("HVLM_ZustandLadeablauf")
        lines.append(f"Charging sequence state: {state or 'INDETERMINATE'}")
        lines.append("Connector evidence: kein_Stecker_erkannt on both monitored connector paths in the prerequisite-focused BLF scan.")
        lines.append("Control-pilot evidence: path A remained in State A; path B reported kein_Zustand_erkannt.")
        lines.append("Control-pilot fault status: kein_Fehler on both monitored paths.")
        lines.append("CP current/protocol evidence: no usable charging-current capability or active charging communication protocol was observed.")
        lines.append("Vehicle charging capability evidence: HVK_Ladebereit reported AC_DC_und_Induktiv_Ladebereit while the HVLM remained in standby.")
        lines.append("Engineering conclusion: The HVLM did not detect a charging connector or establish a valid control-pilot charging state, so charging prerequisites were not fulfilled and charging progression did not begin.")
        lines.append("The BLF does not establish whether no connector was physically present or whether a present connector, cable, EVSE, inlet, or detection circuit was not recognized.")
        lines.append("Root cause remains unconfirmed.")

    def _append_anomalies(self, lines, anomaly_analysis):
        if not anomaly_analysis:
            lines.append("Vehicle-wide signal anomaly analysis: NOT SUPPLIED")
            return
        findings = anomaly_analysis.get("findings", [])
        if not findings:
            lines.append("No supported vehicle-signal anomaly was identified from the supplied decoded evidence.")
            return
        for finding in findings:
            lines.append(f"{finding.get('signal')}: {finding.get('severity', 'INDETERMINATE')} OBSERVED")
            can_id = finding.get("arbitration_id")
            if isinstance(can_id, int):
                lines.append(f"CAN ID: 0x{can_id:X}")
            if finding.get("message_name"):
                lines.append(f"Message: {finding['message_name']}")
            lines.append(f"Abnormal observations: {finding.get('occurrences', 0):,}")
            value_counts = finding.get("value_counts")
            if value_counts:
                lines.append("Observed values: " + ", ".join(f"{value}={count:,}" for value, count in value_counts.items()))
            lines.append(f"State transitions: {len(finding.get('transitions', []))}")
            lines.append(f"Recovery observed: {'YES' if finding.get('recovered') else 'NO'}")
            lines.append("")

    def _append_correlation(self, lines, correlation):
        if not correlation:
            lines.append("Charging-to-fault correlation: NOT SUPPLIED")
            return
        intervals = correlation.get("fault_intervals", [])
        lines.append(f"Fault signal: {correlation.get('fault_signal', 'Unknown')}")
        lines.append(f"Fault intervals: {correlation.get('fault_interval_count', len(intervals))}")
        lines.append(f"Recovered intervals: {correlation.get('recovered_interval_count', 0)}")
        lines.append(f"Persistent at trace end: {'YES' if correlation.get('persistent_at_end') else 'NO'}")
        total_abnormal = sum(interval.get("abnormal_samples", 0) for interval in intervals)
        lines.append(f"Total fault-state observations: {total_abnormal:,}")
        changed = any(interval.get("charging_state_changed_during_fault") for interval in intervals)
        progressed = any(interval.get("charging_progressed_during_fault") for interval in intervals)
        lines.append(f"Charging-related state changes during fault intervals: {'YES' if changed else 'NO'}")
        lines.append(f"Charging sequence progressed during fault intervals: {'YES' if progressed else 'NO'}")
        start_states = self._common_charging_states(intervals, "value_at_fault_start")
        for signal, values in start_states.items():
            lines.append(f"{signal} during fault: {', '.join(values)}")
        lines.append("Causal status: UNCONFIRMED")
        lines.append("Engineering interpretation: The fault was concurrent with the absence of charging progression. Charging did not progress after observed fault recoveries, so the available evidence does not establish the fault as the charging root cause.")

    def _common_charging_states(self, intervals, field):
        states = {}
        for interval in intervals:
            for signal, data in interval.get("charging_state", {}).items():
                value = data.get(field)
                if value is None:
                    continue
                states.setdefault(signal, [])
                text = str(value)
                if text not in states[signal]:
                    states[signal].append(text)
        return states

    def _append_inventory(self, lines, inventory):
        ecus = getattr(inventory, "ecus", None)
        if ecus is None:
            ecus = getattr(inventory, "ecu_inventory", None)
        ecu_items = list(ecus.values()) if isinstance(ecus, dict) else list(ecus or [])
        lines.append(f"ECU inventory observed: {'CONFIRMED' if ecu_items else 'NOT OBSERVED'}")
        lines.append(f"Detected ECUs: {len(ecu_items)}")
        for ecu in ecu_items:
            ecu_id = getattr(ecu, "ecu_id", None) or getattr(ecu, "name", None) or str(ecu)
            evidence = getattr(ecu, "evidence", None)
            count = len(evidence) if evidence is not None else getattr(ecu, "observed_evidence_count", None)
            lines.append(f"{ecu_id}: evidence={count}" if count is not None else str(ecu_id))

    def _append_can_inventory(self, lines, blf_inventory, statistics):
        source = statistics if statistics is not None else blf_inventory
        if source is None:
            lines.append("CAN inventory/statistics: NOT SUPPLIED")
            return
        total_frames = getattr(source, "total_frames", None)
        unique_ids = getattr(source, "unique_can_ids", None)
        duration = getattr(source, "duration_seconds", None)
        channels = getattr(blf_inventory, "channels", None) if blf_inventory is not None else None
        fps = getattr(source, "frames_per_second", None)
        busiest_id = getattr(source, "busiest_can_id", None)
        busiest_channel = getattr(source, "busiest_channel", None)
        if total_frames is not None:
            lines.append(f"Total CAN frames: {total_frames:,}")
        if unique_ids is not None:
            lines.append(f"Unique CAN IDs: {unique_ids:,}")
        if channels is not None:
            lines.append(f"Observed channels: {channels}")
        if duration is not None:
            lines.append(f"Trace duration: {duration:.3f} seconds")
        if fps is not None:
            lines.append(f"Average traffic rate: {fps:,.3f} frames/second")
        if busiest_id is not None:
            lines.append(f"Busiest CAN ID: 0x{busiest_id:X}")
        if busiest_channel is not None:
            lines.append(f"Busiest channel: {busiest_channel}")

    def _append_limitations(self, lines, charging_analysis, anomaly_analysis, correlation):
        if charging_analysis and charging_analysis.get("unavailable_signals"):
            lines.append("Some target charging signals were unavailable in the current decoded BLF evidence, so their states and causal contribution remain INDETERMINATE.")
        if anomaly_analysis:
            lines.append("Vehicle-signal findings are limited to signals covered by the available DBC and the implemented decoded-state classification rules.")
        if correlation:
            lines.append("Temporal correlation does not establish causation; the correlated vehicle fault is not classified as the charging root cause without additional causal evidence.")
        lines.append("A charging condition is not classified as normal merely because no matching fault rule was observed.")

    def _vin(self, inventory) -> str:
        vehicle = getattr(inventory, "vehicle", None)
        value = getattr(vehicle, "vin", None) if vehicle is not None else None
        if not value:
            value = getattr(inventory, "vin", None)
        return str(value) if value else "Not detected"

    def _vin_status(self, inventory) -> str:
        return "CONFIRMED" if self._vin(inventory) != "Not detected" else "NOT OBSERVED"

    def _format_timestamp(self, value) -> str:
        return f"{value:.6f}" if isinstance(value, (int, float)) else str(value)
