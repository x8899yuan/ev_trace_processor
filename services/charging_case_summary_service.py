from pathlib import Path


class ChargingCaseSummaryService:
    def generate_summary(self, signal_values: dict[str, object], findings: list[str], output_dir: Path = Path("reports/charging")) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        summary_path = output_dir / "charging_case_summary.txt"
        normalized = {name: self._normalize(value) for name, value in signal_values.items()}
        cp_display_values = {name: str(value).strip() for name, value in signal_values.items()}
        evidence = self._analyze(normalized, findings, cp_display_values)
        lines = ["CHARGING CASE SUMMARY", "=" * 80, "", "EXECUTIVE SUMMARY", "-" * 80, *evidence["executive_summary"], "", "CHARGING PROGRESSION", "-" * 80, *self._progression_lines(evidence), "", "ENGINEERING CONCLUSION", "-" * 80, *evidence["engineering_conclusion"], "", "SUPPORTING SIGNAL EVIDENCE", "-" * 80, *self._signal_lines(signal_values), "", "ANALYSIS FINDINGS", "-" * 80, *self._finding_lines(findings), "", "ROOT-CAUSE STATUS", "-" * 80, *evidence["root_cause_status"], "", "NEXT DIAGNOSTIC STEPS", "-" * 80, *evidence["next_steps"], "", "FINAL CONCLUSION", "-" * 80, *evidence["final_conclusion"], ""]
        summary_path.write_text("\n".join(lines), encoding="utf-8")
        return summary_path

    def _analyze(self, signals: dict[str, str], findings: list[str], display_signals: dict[str, str]) -> dict[str, object]:
        finding_text = " | ".join(findings).lower()
        connector = self._state(signals, ("HVLM_Steckerstatus_A", "HVLM_Steckerstatus_B"), self._connector_state)
        cp_state = self._first_value(signals, ("HVLM_CP_State_A", "HVLM_CP_State_B"))
        cp_display = self._first_value(display_signals, ("HVLM_CP_State_A", "HVLM_CP_State_B"))
        current = self._first_value(signals, ("HVLM_CP_MaxStrom_A", "HVLM_CP_MaxStrom_B"))
        request = self._state(signals, ("HVLM_Ladevorgang_Anf",), self._request_state)
        prerequisites = self._state(signals, ("HVLM_ZustandLadeablauf",), self._prerequisite_state)
        workflow = self._first_value(signals, ("HVLM_ZustandLadeablauf",))
        has_evidence = bool(signals or findings)
        error = self._contains_any(workflow, ("error", "fehler", "abbruch", "abort")) or self._contains_any(finding_text, ("state machine reports an error", "charging aborted", "charging workflow entered an error"))
        completed = self._contains_any(workflow, ("completed", "complete", "beendet", "abgeschlossen")) and not error
        active = self._contains_any(workflow, ("charging_active", "laden_aktiv", "active charging", "charge_active"))
        requested = request == "Yes"
        not_requested = request == "No" or "charging was not requested" in finding_text
        interface_not_established = connector == "No" or self._cp_is_unestablished(cp_state)
        prereq_not_met = prerequisites == "No" or "readiness not achieved" in finding_text or "not ready for charging" in finding_text
        permission_denied = "charging permission denied" in finding_text
        started = "Yes" if active or completed else "No" if not_requested or prereq_not_met or interface_not_established else "Unknown"
        if completed: classification = "COMPLETED"
        elif error and started == "Yes": classification = "STARTED_THEN_INTERRUPTED"
        elif error: classification = "ERROR_BEFORE_START"
        elif active: classification = "ACTIVE"
        elif permission_denied: classification = "PERMISSION_DENIED"
        elif requested and prereq_not_met: classification = "REQUESTED_PREREQUISITES_NOT_MET"
        elif requested and started != "Yes": classification = "REQUESTED_NOT_STARTED"
        elif interface_not_established and not_requested: classification = "INTERFACE_NOT_ESTABLISHED"
        elif prereq_not_met and not_requested: classification = "PREREQUISITES_NOT_MET"
        elif not_requested: classification = "NOT_REQUESTED"
        elif not has_evidence: classification = "INSUFFICIENT_EVIDENCE"
        else: classification = "UNDETERMINED"
        text = self._classification_text(classification)
        progression = {"Connector detected": connector, "Control Pilot state": cp_display or "Unknown", "Available charging current": self._format_current(current), "Charging requested": request, "Charging prerequisites satisfied": prerequisites, "Charging started": started, "Charging completed": "Yes" if completed else "No" if started == "Yes" or error else "Not applicable" if started == "No" else "Unknown"}
        explicit_root_causes = [item for item in findings if item.startswith("Root Cause:")]
        root_status = [*explicit_root_causes, "The assigned root cause is reported from the supplied analysis findings."] if explicit_root_causes else [text["localization"], "The available evidence does not establish a definitive underlying physical root cause."]
        return {"classification": classification, "progression": progression, "executive_summary": text["executive"], "engineering_conclusion": text["conclusion"], "root_cause_status": root_status, "next_steps": text["steps"], "final_conclusion": text["final"]}

    def _classification_text(self, classification: str) -> dict[str, list[str]]:
        cases = {
            "COMPLETED": {"executive": ["The analyzed evidence shows completed charging progression."], "conclusion": ["Charging progressed to a completed state in the available trace evidence."], "localization": "No charging-stage failure was localized in the completed sequence.", "steps": ["1. No failure-specific charging diagnosis is indicated by this sequence.", "2. Review duration, current, voltage, and energy transfer if charging quality must be assessed."], "final": ["A completed charging sequence was observed."]},
            "ACTIVE": {"executive": ["The analyzed evidence shows an active charging state, but completion was not established."], "conclusion": ["Charging initiation succeeded and active charging was observed."], "localization": "No charging-initiation failure was localized.", "steps": ["1. Review later trace coverage for completion or interruption.", "2. Correlate charging current, voltage, and energy transfer during the active interval."], "final": ["Active charging was observed; completion could not be confirmed from the available evidence."]},
            "STARTED_THEN_INTERRUPTED": {"executive": ["Charging started but was later interrupted or entered an error state."], "conclusion": ["The failure occurred after charging initiation, not during initial connector recognition."], "localization": "The charging issue is localized after the start of active charging.", "steps": ["1. Correlate the first abort/error transition with HV voltage and current.", "2. Review contactor, isolation, thermal, charger, and EVSE fault evidence at that timestamp.", "3. Compare DLT, MF4, or PCAP evidence from the same interval when available."], "final": ["Charging initiated and subsequently stopped; the triggering physical cause remains evidence-dependent."]},
            "ERROR_BEFORE_START": {"executive": ["The charging workflow entered an error condition before active charging was established."], "conclusion": ["Charging did not start because the workflow entered an error state during initiation."], "localization": "The issue is localized to charging initiation before energy transfer.", "steps": ["1. Inspect the first charging error transition and concurrent diagnostic signals.", "2. Check authorization, readiness, contactor, isolation, and EVSE interface evidence."], "final": ["Charging initiation failed with an observed workflow error; the physical cause requires correlated fault evidence."]},
            "PERMISSION_DENIED": {"executive": ["Charging did not proceed because charging permission was denied."], "conclusion": ["The charging sequence was blocked at the authorization or permission stage."], "localization": "The issue is localized to charging authorization or permission handling.", "steps": ["1. Review charging authorization and enable conditions.", "2. Correlate backend, contract, user-setting, and control-module permission signals."], "final": ["Charging was blocked by a denied permission condition; the cause of that denial requires supporting authorization evidence."]},
            "REQUESTED_PREREQUISITES_NOT_MET": {"executive": ["A charging request was observed, but charging prerequisites were not satisfied."], "conclusion": ["Charging was requested but did not start because readiness conditions remained incomplete."], "localization": "The issue is localized between the charging request and readiness completion.", "steps": ["1. Identify the first unsatisfied charging prerequisite.", "2. Check vehicle readiness, HV contactors, isolation, thermal limits, and EVSE readiness.", "3. Correlate the request timestamp with DLT or MF4 evidence when available."], "final": ["Charging was requested but remained blocked by unsatisfied prerequisites."]},
            "REQUESTED_NOT_STARTED": {"executive": ["A charging request was observed, but active charging was not established."], "conclusion": ["Charging progression stopped after the request and before confirmed energy transfer."], "localization": "The issue is localized after the charging request and before active charging.", "steps": ["1. Review readiness, permission, EVSE response, and contactor transitions after the request.", "2. Check current and voltage evidence for attempted energy transfer."], "final": ["Charging was requested but a confirmed charging start was not observed."]},
            "INTERFACE_NOT_ESTABLISHED": {"executive": ["Charging did not progress beyond the interface/prerequisite stage."], "conclusion": ["The charging interface was not established and no active charging request was observed."], "localization": "The issue is localized before charging prerequisites and an active charging request were established.", "steps": ["1. Verify charging connector and inlet detection.", "2. Check Control Pilot state and expected transitions.", "3. Check Proximity Pilot or plug-presence detection where available.", "4. Verify EVSE signaling, interface wiring, and charging-control-module inputs."], "final": ["Charging remained at the interface/prerequisite stage and did not start."]},
            "PREREQUISITES_NOT_MET": {"executive": ["Charging did not progress because charging prerequisites were not satisfied and no active request was observed."], "conclusion": ["The charging sequence remained in a prerequisite/standby condition."], "localization": "The issue is localized to the charging prerequisite stage.", "steps": ["1. Identify the unsatisfied readiness conditions.", "2. Check connector, CP/PP, vehicle readiness, HV contactor, isolation, and EVSE status evidence."], "final": ["Charging did not start because the sequence remained in the prerequisite/standby stage."]},
            "NOT_REQUESTED": {"executive": ["No active charging request was observed in the analyzed evidence."], "conclusion": ["Charging did not start because the charging workflow was not requested during the observed interval."], "localization": "The observed sequence stops before an active charging request.", "steps": ["1. Determine whether a charging attempt was expected during the trace interval.", "2. If expected, inspect request-generation, user-command, authorization, connector, and EVSE conditions."], "final": ["Charging was not requested during the analyzed interval; the reason remains dependent on upstream evidence."]},
            "INSUFFICIENT_EVIDENCE": {"executive": ["The available inputs do not contain enough charging evidence to classify charging progression."], "conclusion": ["No evidence-supported charging-stage conclusion can be assigned."], "localization": "The charging sequence could not be localized.", "steps": ["1. Confirm that charging signals were decoded from the BLF.", "2. Verify DBC coverage and capture timing for connector, CP, request, readiness, and charging-state signals."], "final": ["Charging progression is undetermined because the available evidence is insufficient."]},
            "UNDETERMINED": {"executive": ["Charging evidence was found, but the observed combination does not support a definitive progression classification."], "conclusion": ["The charging stage remains undetermined from the available signal combination."], "localization": "A reliable stopping stage could not be assigned.", "steps": ["1. Review the decoded signal timeline for transitions rather than final values alone.", "2. Expand DBC coverage for connector, CP, request, readiness, active charging, and completion states."], "final": ["Charging progression remains undetermined; additional or time-resolved evidence is required."]},
        }
        return cases[classification]

    def _progression_lines(self, evidence: dict[str, object]) -> list[str]:
        progression = evidence["progression"]
        width = max(len(name) for name in progression)
        return [f"{name + ':':<{width + 2}} {value}" for name, value in progression.items()]

    def _signal_lines(self, signal_values: dict[str, object]) -> list[str]:
        if not signal_values:
            return ["No supporting charging signals were supplied."]
        lines = []
        for name, raw_value in signal_values.items():
            value = str(raw_value)
            meaning = self._meaning(name, value)
            lines.extend((name, f"  Value: {value}", f"  Meaning: {meaning}", ""))
        return lines[:-1]

    def _finding_lines(self, findings: list[str]) -> list[str]:
        return [f"- {finding}" for finding in findings] if findings else ["No additional analysis findings were supplied."]

    def _meaning(self, signal_name: str, value: str) -> str:
        normalized = self._normalize(value)
        if signal_name.startswith("HVLM_CP_MaxStrom_"):
            try:
                return f"Maximum current indicated by the Control Pilot: {float(value):.1f} A"
            except ValueError:
                pass
        mappings = (("kein_stecker_erkannt", "No charging connector detected"), ("stecker_erkannt", "Charging connector detected"), ("laden_nicht_angefordert", "Charging not requested"), ("laden_angefordert", "Charging requested"), ("stby_ladevorbed_nicht_erfuellt", "Standby - charging prerequisites not satisfied"), ("kein_zustand_erkannt", "No state detected"), ("nicht_bekannt", "Value not known"), ("kein hv fehler", "No HV heater fault detected at this observation"))
        for token, meaning in mappings:
            if token in normalized:
                return meaning
        if normalized == "a":
            return "Control Pilot State A - charging interface not established"
        return "Decoded signal value; no additional translation available"

    def _connector_state(self, value: str) -> str:
        if self._contains_any(value, ("kein_stecker", "not detected", "not connected", "unplugged")): return "No"
        if self._contains_any(value, ("stecker_erkannt", "detected", "connected", "plugged")): return "Yes"
        return "Unknown"

    def _request_state(self, value: str) -> str:
        if self._contains_any(value, ("nicht_angefordert", "not requested", "inactive")): return "No"
        if self._contains_any(value, ("angefordert", "requested", "active")): return "Yes"
        return "Unknown"

    def _prerequisite_state(self, value: str) -> str:
        if self._contains_any(value, ("nicht_erfuellt", "not satisfied", "not ready")): return "No"
        if self._contains_any(value, ("erfuellt", "satisfied", "ready")): return "Yes"
        return "Unknown"

    def _state(self, signals: dict[str, str], names: tuple[str, ...], evaluator) -> str:
        states = [evaluator(signals[name]) for name in names if name in signals]
        if "Yes" in states: return "Yes"
        if "No" in states: return "No"
        return "Unknown"

    def _first_value(self, signals: dict[str, str], names: tuple[str, ...]) -> str:
        for name in names:
            value = signals.get(name)
            if value and not self._contains_any(value.lower(), ("nicht_bekannt", "unknown", "kein_zustand_erkannt")):
                return value
        return ""

    def _cp_is_unestablished(self, value: str) -> bool:
        return value == "a" or self._contains_any(value, ("state a", "kein_zustand", "not detected"))

    def _format_current(self, value: str) -> str:
        if not value: return "Unknown"
        try: return f"{float(value):g} A"
        except ValueError: return value

    def _normalize(self, value: object) -> str:
        return str(value).strip().lower()

    def _contains_any(self, text: str, values: tuple[str, ...]) -> bool:
        return any(value in text for value in values)
