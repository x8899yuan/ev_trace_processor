from pathlib import Path
from services.engineering_value_formatter import EngineeringValueFormatter


class TestSessionSummaryService:
    TRACE_ORDER = ("blf", "dlt", "pcap", "mf4")
    TRACE_LABELS = {"blf": "BLF", "dlt": "DLT", "pcap": "PCAP", "mf4": "MF4"}

    def save_summary(self, *, vehicle_identity=None, blf=None, dlt=None, pcap=None, mf4=None, run_id: str | None = None) -> Path:
        traces = self._validated_traces(blf=blf, dlt=dlt, pcap=pcap, mf4=mf4)
        output = self._output_path(run_id)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.generate_summary(vehicle_identity=vehicle_identity, **traces), encoding="utf-8")
        return output.resolve()

    def generate_summary(self, *, vehicle_identity=None, blf=None, dlt=None, pcap=None, mf4=None) -> str:
        traces = self._validated_traces(blf=blf, dlt=dlt, pcap=pcap, mf4=mf4)
        lines = ["Vehicle Test Session Engineering Summary", "=" * 80]
        if vehicle_identity and vehicle_identity.get("vin"):
            lines.extend(["", "Vehicle Identity", "-" * 80])
            lines.append(f"VIN: {vehicle_identity['vin']}")
            lines.append(f"VIN Status: {vehicle_identity.get('status', 'CONFIRMED')}")
            lines.append(f"VIN Evidence Source: {vehicle_identity.get('source', 'NOT SUPPLIED')}")
        lines.extend(["", "Trace Coverage", "-" * 80])
        for key in self.TRACE_ORDER:
            result = traces[key]
            if result:
                lines.append(f"{self.TRACE_LABELS[key]}: ANALYZED | {self._source_name(result)}")
        for key in self.TRACE_ORDER:
            result = traces[key]
            if result:
                lines.extend(["", self.TRACE_LABELS[key], "-" * 80])
                self._append_trace(lines, key, result)
        if blf and mf4:
            lines.extend(["", "Cross-Trace Engineering Interpretation", "-" * 80])
            agreement = self._charging_agreement(blf, mf4)
            if agreement == "SUPPORTED_BY_MULTIPLE_TRACES":
                lines.append("The current session evidence independently confirms the same unmet charging prerequisites in both BLF and MF4 evidence.")
            lines.append(f"Evidence strength: {agreement}")
            lines.append("Causal status: UNCONFIRMED")
        lines.extend(["", "Evidence Limitations", "-" * 80])
        lines.append("Input traces are treated as belonging to the same vehicle and testing session. The user is responsible for supplying a coherent trace set.")
        lines.append("Cross-trace agreement strengthens an engineering finding but does not automatically establish root cause.")
        return EngineeringValueFormatter().format_text("\n".join(lines) + "\n")

    def _validated_traces(self, **traces) -> dict:
        normalized = {key: traces.get(key) for key in self.TRACE_ORDER}
        if not any(normalized.values()):
            raise ValueError("No supported traces were provided. Supply at least one BLF, DLT, PCAP, or MF4 trace.")
        return normalized

    def _append_trace(self, lines, key, result):
        if key in {"blf", "mf4"}:
            for field, label in (
                ("charging_progression", "Charging progression"),
                ("connector_recognition", "Connector recognition"),
                ("control_pilot_recognition", "Control-pilot recognition"),
                ("root_cause_status", "Root cause status"),
            ):
                if field in result:
                    lines.append(f"{label}: {result[field]}")
        if key == "blf":
            self._append_values(lines, result.get("fault_findings"))
        elif key == "dlt":
            self._append_values(lines, result.get("fault_findings"))
            category_counts = result.get("finding_category_counts") or {}
            for category in ("critical", "error", "warning", "keyword_observation"):
                if category in category_counts:
                    lines.append(f"{category.upper()} findings: {category_counts[category]}")
            if result.get("severity_counts"):
                lines.append("Severity counts: " + ", ".join(f"{name}={count}" for name, count in result["severity_counts"].items()))
        elif key == "pcap":
            network = result.get("network_assessment") or {}
            lines.append(f"Network communication: {network.get('status', 'INDETERMINATE')}")
            dominant = network.get("dominant_protocol")
            if dominant:
                lines.append(f"Dominant observed protocol: {dominant}")
            din = result.get("din70121_assessment")
            if din:
                lines.append(f"DIN 70121: {din.get('status', 'INDETERMINATE')}")
                if din.get("selected_protocol"):
                    lines.append(f"DIN 70121 negotiated protocol: {din['selected_protocol']}")
                if din.get("furthest_message"):
                    lines.append(f"DIN 70121 progression: {din['furthest_message']}")
                if din.get("session_completion"):
                    lines.append(f"DIN 70121 session completion: {din['session_completion']}")
            tls = result.get("iso15118_tls_assessment")
            if tls:
                lines.append(f"ISO 15118 / TLS: {tls.get('status', 'INDETERMINATE')}")
                if tls.get("tls_version"):
                    lines.append(f"TLS version: {tls['tls_version']}")
                if "server_certificate_observed" in tls:
                    lines.append(f"TLS server certificate: {'OBSERVED' if tls['server_certificate_observed'] else 'NOT_OBSERVED'}")
                if "client_certificate_observed" in tls:
                    lines.append(f"TLS client-certificate authentication: {'OBSERVED' if tls['client_certificate_observed'] else 'NOT_OBSERVED'}")
        elif key == "mf4":
            if "cp_fault_observed" in result:
                lines.append(f"Explicit CP fault observed: {'YES' if result['cp_fault_observed'] else 'NO'}")
            findings = result.get("findings", {})
            if isinstance(findings, dict):
                for name, value in findings.items():
                    if isinstance(value, (str, int, float, bool)):
                        lines.append(f"{name}: {value}")

    def _append_values(self, lines, values):
        if not values:
            return
        for value in values:
            lines.append(str(value))

    def _charging_agreement(self, blf, mf4) -> str:
        expected = ("NOT_OBSERVED", "NOT_RECOGNIZED", "NOT_ESTABLISHED")
        keys = ("charging_progression", "connector_recognition", "control_pilot_recognition")
        if tuple(blf.get(key) for key in keys) == expected and tuple(mf4.get(key) for key in keys) == expected:
            return "SUPPORTED_BY_MULTIPLE_TRACES"
        return "INDETERMINATE"

    def _source_name(self, result) -> str:
        source = result.get("source_file") or result.get("source")
        if source:
            return Path(str(source)).name
        sources = result.get("source_files", [])
        if sources:
            return ", ".join(Path(str(value)).name for value in sources)
        return "source not supplied"

    def _output_path(self, run_id: str | None = None) -> Path:
        name = f"session_summary_{run_id}.txt" if run_id else "session_summary.txt"
        return Path(__file__).resolve().parent.parent / "reports" / name
