from pathlib import Path

from services.engineering_value_formatter import EngineeringValueFormatter
from services.html_report_renderer import HtmlReportRenderer


class TestSessionHtmlReportService:
    __test__ = False
    TRACE_ORDER = ("blf", "dlt", "pcap", "mf4")
    TRACE_LABELS = {"blf": "BLF", "dlt": "DLT", "pcap": "PCAP / V2G", "mf4": "MF4"}

    def __init__(self, renderer: HtmlReportRenderer | None = None) -> None:
        self._renderer = renderer if renderer is not None else HtmlReportRenderer()

    def save_report(self, session: dict, manifest: dict, run_id: str | None = None) -> Path:
        output = self._output_path(run_id)
        return self._renderer.write_page(output, self.generate_report(session, manifest))

    def generate_report(self, session: dict, manifest: dict) -> str:
        traces = {key: session.get(key) for key in self.TRACE_ORDER}
        if not any(traces.values()):
            raise ValueError("No supported traces were provided. Supply at least one BLF, DLT, PCAP, or MF4 trace.")
        sections = []
        vehicle = session.get("vehicle_identity") or {}
        if vehicle.get("vin"):
            sections.append({
                "title": "Vehicle Identity",
                "rows": [
                    {"label": "VIN", "value": vehicle["vin"]},
                    {"label": "VIN Status", "value": vehicle.get("status", "CONFIRMED")},
                    {"label": "VIN Evidence Source", "value": vehicle.get("source", "NOT SUPPLIED")},
                ],
            })
        sections.append({
            "title": "Trace Coverage",
            "rows": [{"label": self.TRACE_LABELS[key], "value": "ANALYZED"} for key in self.TRACE_ORDER if traces[key]],
        })
        for key in self.TRACE_ORDER:
            if traces[key]:
                sections.append(self._trace_section(key, traces[key], manifest.get("traces", {}).get(key.upper(), {})))
        if traces["blf"] and traces["mf4"]:
            agreement = self._charging_agreement(traces["blf"], traces["mf4"])
            text = "The current session evidence independently confirms the same unmet charging prerequisites in both BLF and MF4 evidence." if agreement == "SUPPORTED_BY_MULTIPLE_TRACES" else "Cross-trace charging-prerequisite agreement remains indeterminate."
            sections.append({
                "title": "Cross-Trace Engineering Interpretation",
                "text": text,
                "rows": [
                    {"label": "Evidence strength", "value": agreement},
                    {"label": "Causal status", "value": "UNCONFIRMED"},
                ],
            })
        sections.append({
            "title": "Evidence Limitations",
            "items": [
                "Input traces are treated as belonging to the same vehicle and testing session. The user is responsible for supplying a coherent trace set.",
                "Cross-trace agreement strengthens an engineering finding but does not automatically establish root cause.",
            ],
        })
        html = self._renderer.render_page(
            title="Vehicle Test Session Engineering Summary",
            subtitle="Available trace evidence with trace-local provenance",
            sections=sections,
        )
        return EngineeringValueFormatter().format_text(html)

    def _trace_section(self, key, result, manifest_entry):
        source_files = result.get("source_files", [])
        if key == "pcap" and source_files:
            source_text = "Source: " + ", ".join(Path(str(value)).name for value in source_files)
        else:
            source_text = f"Source: {self._source_name(result)}"
        section = {"title": self.TRACE_LABELS[key], "text": source_text, "rows": [], "items": [], "links": []}
        if key in {"blf", "mf4"}:
            for field, label in (
                ("charging_progression", "Charging progression"),
                ("connector_recognition", "Connector recognition"),
                ("control_pilot_recognition", "Control-pilot recognition"),
                ("root_cause_status", "Root cause status"),
            ):
                if field in result:
                    section["rows"].append({"label": label, "value": result[field]})
        if key in {"blf", "dlt"}:
            section["items"].extend(result.get("fault_findings", []))
        if key == "dlt" and result.get("severity_counts"):
            section["items"].append("Severity counts: " + ", ".join(f"{name}={count}" for name, count in result["severity_counts"].items()))
        if key == "pcap":
            network = result.get("network_assessment") or {}
            section["rows"].append({"label": "Network communication", "value": network.get("status", "INDETERMINATE")})
            if network.get("dominant_protocol"):
                section["rows"].append({"label": "Dominant observed protocol", "value": network["dominant_protocol"]})
            din = result.get("din70121_assessment")
            if din:
                section["rows"].append({"label": "DIN 70121", "value": din.get("status", "INDETERMINATE")})
                if din.get("furthest_message"):
                    section["rows"].append({"label": "DIN 70121 progression", "value": din["furthest_message"]})
            tls = result.get("iso15118_tls_assessment")
            if tls:
                section["rows"].append({"label": "ISO 15118 / TLS", "value": tls.get("status", "INDETERMINATE")})
                if tls.get("tls_version"):
                    section["rows"].append({"label": "TLS version", "value": tls["tls_version"]})
        section["links"] = self._renderer.build_manifest_links(manifest_entry.get("reports", []))
        if key == "mf4" and "cp_fault_observed" in result:
            section["rows"].append({"label": "Explicit CP fault observed", "value": "YES" if result["cp_fault_observed"] else "NO"})
        return section

    def _charging_agreement(self, blf, mf4):
        expected = ("NOT_OBSERVED", "NOT_RECOGNIZED", "NOT_ESTABLISHED")
        keys = ("charging_progression", "connector_recognition", "control_pilot_recognition")
        if tuple(blf.get(key) for key in keys) == expected and tuple(mf4.get(key) for key in keys) == expected:
            return "SUPPORTED_BY_MULTIPLE_TRACES"
        return "INDETERMINATE"

    def _source_name(self, result):
        source = result.get("source_file") or result.get("source")
        if source:
            return Path(str(source)).name
        sources = result.get("source_files", [])
        if sources:
            return ", ".join(Path(str(value)).name for value in sources)
        return "source not supplied"

    def _output_path(self, run_id: str | None = None):
        name = f"session_summary_{run_id}.html" if run_id else "session_summary.html"
        return Path(__file__).resolve().parent.parent / "reports" / name
