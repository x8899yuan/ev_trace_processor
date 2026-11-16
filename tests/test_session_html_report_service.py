from pathlib import Path

from services.html_report_renderer import HtmlReportRenderer


class TestSessionHtmlReportService:
    __test__ = False

    def __init__(self, renderer: HtmlReportRenderer | None = None) -> None:
        self._renderer = renderer if renderer is not None else HtmlReportRenderer()

    def save_report(self, session: dict, manifest: dict) -> Path:
        output_path = self._output_path()
        html = self.generate_report(session, manifest)
        return self._renderer.write_page(output_path, html)

    def _output_path(self) -> Path:
        return Path(__file__).resolve().parent.parent / "reports" / "test_session_summary.html"

    def generate_report(self, session: dict, manifest: dict) -> str:
        vehicle = session.get("vehicle_identity") or {}
        blf = session.get("blf")
        dlt = session.get("dlt")
        pcap = session.get("pcap")
        mf4 = session.get("mf4")
        traces = manifest.get("traces", {})
        sections = [
            self._vehicle_section(vehicle),
            self._coverage_section(blf, dlt, pcap, mf4),
            self._charging_section(blf, mf4),
            self._blf_section(blf, traces.get("BLF", {})),
            self._dlt_section(dlt, traces.get("DLT", {})),
            self._pcap_section(pcap, traces.get("PCAP", {})),
            self._mf4_section(mf4, traces.get("MF4", {})),
            self._cross_trace_section(blf, mf4),
            self._limitations_section(vehicle),
        ]
        return self._renderer.render_page(
            title="Vehicle Test Session Engineering Summary",
            subtitle="BLF, DLT, PCAP and MF4 evidence with trace-local provenance",
            sections=sections,
        )

    def _vehicle_section(self, vehicle: dict) -> dict:
        independent = vehicle.get("independent_trace_evidence", {})
        rows = [
            {"label": "VIN", "value": vehicle.get("vin", "NOT OBSERVED")},
            {"label": "Vehicle identity status", "value": vehicle.get("status", "INDETERMINATE")},
            {"label": "Confirmed evidence source", "value": vehicle.get("source", "NOT SUPPLIED")},
        ]
        for trace_type in ("BLF", "DLT", "PCAP", "MF4"):
            if trace_type in independent:
                rows.append({"label": f"{trace_type} independent VIN evidence", "value": independent[trace_type]})
        return {"title": "Vehicle Identity", "rows": rows}

    def _coverage_section(self, blf, dlt, pcap, mf4) -> dict:
        return {
            "title": "Trace Coverage",
            "rows": [
                {"label": "BLF", "value": "ANALYZED" if blf else "NOT SUPPLIED"},
                {"label": "DLT", "value": "ANALYZED" if dlt else "NOT SUPPLIED"},
                {"label": "PCAP", "value": "ANALYZED" if pcap else "NOT SUPPLIED"},
                {"label": "MF4", "value": "ANALYZED" if mf4 else "NOT SUPPLIED"},
            ],
        }

    def _charging_section(self, blf, mf4) -> dict:
        agreement = self._charging_agreement(blf, mf4)
        return {
            "title": "Charging Assessment",
            "rows": [
                {"label": "BLF charging progression", "value": self._value(blf, "charging_progression")},
                {"label": "BLF connector recognition", "value": self._value(blf, "connector_recognition")},
                {"label": "BLF control-pilot recognition", "value": self._value(blf, "control_pilot_recognition")},
                {"label": "MF4 charging progression", "value": self._value(mf4, "charging_progression")},
                {"label": "MF4 connector recognition", "value": self._value(mf4, "connector_recognition")},
                {"label": "MF4 control-pilot recognition", "value": self._value(mf4, "control_pilot_recognition")},
                {"label": "Cross-trace evidence strength", "value": agreement},
                {"label": "Overall charging root cause", "value": "UNCONFIRMED"},
            ],
        }

    def _blf_section(self, blf, manifest_entry: dict) -> dict:
        items = []
        if blf:
            items.extend(blf.get("fault_findings", []))
        return {
            "title": "BLF",
            "text": self._source_text(blf),
            "items": items,
            "links": self._manifest_links(manifest_entry.get("reports", [])),
        }

    def _dlt_section(self, dlt, manifest_entry: dict) -> dict:
        items = []
        if dlt:
            items.extend(dlt.get("fault_findings", []))
            severity = dlt.get("severity_counts", {})
            if severity:
                items.append("Severity counts: " + ", ".join(f"{key}={value}" for key, value in severity.items()))
        return {
            "title": "DLT",
            "text": self._source_text(dlt),
            "items": items,
            "links": self._manifest_links(manifest_entry.get("reports", [])),
        }

    def _pcap_section(self, pcap, manifest_entry: dict) -> dict:
        items = []
        if pcap:
            items.extend(pcap.get("findings", []))
            din = pcap.get("din70121")
            tls = pcap.get("iso15118_tls")
            if din:
                items.append("DIN 70121 evidence retained with PCAP provenance.")
            if tls:
                items.append("ISO 15118 / TLS evidence retained with PCAP provenance.")
        links = []
        for group_name, group in manifest_entry.get("groups", {}).items():
            for entry in group.get("reports", []):
                if entry.get("html_exists"):
                    links.append({
                        "title": f"{group_name}: {entry.get('title', 'Report')}",
                        "href": entry.get("html"),
                    })
        return {"title": "PCAP / V2G", "text": self._source_text(pcap), "items": items, "links": links}

    def _mf4_section(self, mf4, manifest_entry: dict) -> dict:
        rows = []
        if mf4:
            rows = [
                {"label": "Charging progression", "value": mf4.get("charging_progression", "INDETERMINATE")},
                {"label": "Connector recognition", "value": mf4.get("connector_recognition", "INDETERMINATE")},
                {"label": "Control-pilot recognition", "value": mf4.get("control_pilot_recognition", "INDETERMINATE")},
                {"label": "Explicit CP fault observed", "value": "YES" if mf4.get("cp_fault_observed") else "NO"},
            ]
        return {
            "title": "MF4",
            "text": self._source_text(mf4),
            "rows": rows,
            "links": self._manifest_links(manifest_entry.get("reports", [])),
        }

    def _cross_trace_section(self, blf, mf4) -> dict:
        agreement = self._charging_agreement(blf, mf4)
        if agreement == "SUPPORTED_BY_MULTIPLE_TRACES":
            text = "The current session evidence independently confirms the same unmet charging prerequisites in both BLF and MF4 evidence."
        else:
            text = "Cross-trace charging-prerequisite agreement remains indeterminate."
        return {
            "title": "Cross-Trace Engineering Interpretation",
            "text": text,
            "rows": [
                {"label": "Evidence strength", "value": agreement},
                {"label": "Causal status", "value": "UNCONFIRMED"},
            ],
        }

    def _limitations_section(self, vehicle: dict) -> dict:
        source = vehicle.get("source", "NOT SUPPLIED")
        return {
            "title": "Evidence Limitations",
            "items": [
                f"The session VIN is attributed to its confirmed source: {source}.",
                "Session membership does not imply that every trace independently observed the same vehicle identifier or event.",
                "Cross-trace agreement strengthens an engineering finding but does not automatically establish root cause.",
                "Timestamp-level cross-trace correlation is not performed by this report version.",
                "Absence of connector/control-pilot recognition does not establish whether no connector was physically present or whether a present connector, cable, EVSE, inlet, or detection circuit was not recognized.",
            ],
        }

    def _manifest_links(self, entries: list[dict]) -> list[dict]:
        return self._renderer.build_manifest_links(entries)

    def _source_text(self, result: dict | None) -> str:
        if not result:
            return "Structured trace evidence was not supplied."
        source = result.get("source_file") or result.get("source") or "source not supplied"
        return f"Source: {Path(str(source)).name}"

    def _value(self, result: dict | None, key: str) -> str:
        if not result:
            return "NOT SUPPLIED"
        return result.get(key, "INDETERMINATE")

    def _charging_agreement(self, blf, mf4) -> str:
        if not blf or not mf4:
            return "INDETERMINATE"
        keys = ("charging_progression", "connector_recognition", "control_pilot_recognition")
        expected = ("NOT_OBSERVED", "NOT_RECOGNIZED", "NOT_ESTABLISHED")
        if tuple(blf.get(key) for key in keys) == expected and tuple(mf4.get(key) for key in keys) == expected:
            return "SUPPORTED_BY_MULTIPLE_TRACES"
        return "INDETERMINATE"
