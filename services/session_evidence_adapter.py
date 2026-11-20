from pathlib import Path


class TestSessionEvidenceAdapter:
    def adapt_dlt(self, analysis: dict | None) -> dict | None:
        if not analysis:
            return None
        capture = analysis.get("capture", {})
        source_files = list(capture.get("source_files", []))
        category_counts = dict(analysis.get("finding_category_counts", {}))
        return {
            "source_file": source_files[0] if len(source_files) == 1 else None,
            "source_files": source_files,
            "capture": {
                "trace_count": capture.get("trace_count", 0),
                "event_count": capture.get("event_count", 0),
                "start_timestamp": capture.get("start_timestamp"),
                "end_timestamp": capture.get("end_timestamp"),
                "duration_seconds": capture.get("duration_seconds"),
            },
            "severity_counts": dict(analysis.get("severity_counts", {})),
            "finding_category_counts": category_counts,
            "critical_findings": list(analysis.get("critical_findings", [])),
            "error_findings": list(analysis.get("error_findings", [])),
            "warning_findings": list(analysis.get("warning_findings", [])),
            "keyword_observations": list(analysis.get("keyword_observations", [])),
            "finding_signatures": list(analysis.get("finding_signatures", [])),
            "ecu_counts": dict(analysis.get("ecu_counts", {})),
            "application_counts": dict(analysis.get("application_counts", {})),
            "context_counts": dict(analysis.get("context_counts", {})),
            "fault_findings": self._dlt_fault_findings(category_counts),
        }

    def adapt_pcap(self, analysis: dict | None, *, din70121: dict | None = None, iso15118_tls: dict | None = None) -> dict | None:
        if not analysis and not din70121 and not iso15118_tls:
            return None
        analysis = analysis or {}
        capture = analysis.get("capture", {})
        return {
            "source_file": capture.get("file_path") or capture.get("file_name"),
            "source_files": list(capture.get("source_files", [])),
            "capture": {
                "file_name": capture.get("file_name"),
                "packet_count": capture.get("packet_count", 0),
                "start_timestamp": capture.get("start_timestamp"),
                "end_timestamp": capture.get("end_timestamp"),
                "duration_seconds": capture.get("duration_seconds"),
            },
            "protocol_counts": dict(analysis.get("protocol_counts", {})),
            "vlan_counts": dict(analysis.get("vlan_counts", {})),
            "transition_analysis": dict(analysis.get("transition_analysis", {})),
            "din70121": self._copy_dict(din70121),
            "iso15118_tls": self._copy_dict(iso15118_tls),
            "network_assessment": self._network_assessment(analysis),
            "din70121_assessment": self._din70121_assessment(din70121),
            "iso15118_tls_assessment": self._tls_assessment(iso15118_tls),
        }

    def adapt_asc(self, analysis: dict | None) -> dict | None:
        if not analysis:
            return None
        captures = []
        for item in analysis.get("captures") or []:
            if not isinstance(item, dict):
                continue
            charging = item.get("charging_analysis") or {}
            captures.append(
                {
                    "source_file": item.get("source_file"),
                    "inventory": self._copy_dict(item.get("inventory")),
                    "statistics": self._copy_dict(item.get("statistics")),
                    "charging_analysis": {
                        key: charging.get(key)
                        for key in (
                            "classification",
                            "charging_progression",
                            "connector_recognition",
                            "control_pilot_recognition",
                            "charging_request",
                            "charging_workflow",
                            "root_cause_status",
                            "engineering_conclusion",
                        )
                        if key in charging
                    },
                    "charging_report": item.get("charging_report"),
                }
            )
        return {
            "analysis_status": analysis.get(
                "analysis_status",
                "OBSERVED" if captures else "NOT_OBSERVED",
            ),
            "file_count": int(analysis.get("file_count", len(captures)) or 0),
            "captures": captures,
        }

    def build_session_inputs(self, *, vehicle_identity: dict | None = None, blf: dict | None = None, dlt_analysis: dict | None = None, pcap_analysis: dict | None = None, din70121: dict | None = None, iso15118_tls: dict | None = None, mf4: dict | None = None, asc: dict | None = None) -> dict:
        return {
            "vehicle_identity": vehicle_identity,
            "blf": blf,
            "dlt": self.adapt_dlt(dlt_analysis),
            "pcap": self.adapt_pcap(pcap_analysis, din70121=din70121, iso15118_tls=iso15118_tls),
            "mf4": mf4,
            "asc": self.adapt_asc(asc),
        }

    def _dlt_fault_findings(self, category_counts: dict) -> list[str]:
        rows = []
        for key, label in (("critical", "CRITICAL"), ("error", "ERROR"), ("warning", "WARNING")):
            if key in category_counts:
                rows.append(f"{label} findings: {int(category_counts.get(key, 0) or 0)}")
        if not rows:
            rows.append("No classified critical/error/warning finding totals supplied")
        return rows

    def _pcap_findings(self, analysis: dict, din70121: dict | None, iso15118_tls: dict | None) -> list[str]:
        rows = []
        protocol_counts = analysis.get("protocol_counts", {})
        if protocol_counts:
            rows.append("Observed protocols: " + ", ".join(f"{name}={count}" for name, count in protocol_counts.items()))
        self._append_capture_provenance(rows, "DIN 70121", din70121)
        self._append_capture_provenance(rows, "ISO 15118 / TLS", iso15118_tls)
        if not rows:
            rows.append("No structured PCAP findings supplied")
        return rows

    def _append_capture_provenance(self, rows: list[str], label: str, evidence: dict | None) -> None:
        if not evidence:
            return
        captures = evidence.get("captures")
        if isinstance(captures, list):
            sources = []
            for item in captures:
                if not isinstance(item, dict):
                    continue
                source = item.get("source_file")
                if source:
                    sources.append(Path(str(source)).name)
            if sources:
                rows.append(f"{label} structured analysis: AVAILABLE")
                rows.append(f"{label} source captures: " + ", ".join(sources))
                return
        rows.append(f"{label} structured analysis: AVAILABLE")

    def _network_assessment(self, analysis: dict) -> dict:
        counts = analysis.get("protocol_counts", {})
        dominant = max(counts, key=counts.get) if counts else None
        return {
            "status": "OBSERVED" if counts else "NOT_OBSERVED",
            "dominant_protocol": dominant,
            "protocol_counts": dict(counts),
        }

    def _din70121_assessment(self, evidence: dict | None) -> dict | None:
        if not evidence:
            return None
        status = evidence.get("analysis_status")
        if status is None:
            status = "OBSERVED" if any(
                evidence.get(key)
                for key in ("selected_protocol", "message_count", "furthest_message", "session_completion")
            ) else "INDETERMINATE"
        result = {"status": status}
        captures = evidence.get("captures")
        if isinstance(captures, list):
            result["captures_analyzed"] = len(captures)
        for key in ("selected_protocol", "analysis_status", "message_count", "furthest_message", "session_completion"):
            if key in evidence:
                result[key] = evidence[key]
        return result

    def _tls_assessment(self, evidence: dict | None) -> dict | None:
        if not evidence:
            return None
        status = evidence.get("analysis_status")
        if status is None:
            status = "OBSERVED" if any(
                evidence.get(key) is not None
                for key in ("tls_version", "server_certificate_observed", "client_certificate_observed")
            ) else "INDETERMINATE"
        result = {"status": status}
        captures = evidence.get("captures")
        if isinstance(captures, list):
            result["captures_analyzed"] = len(captures)
        for key in ("tls_version", "analysis_status", "server_certificate_observed", "client_certificate_observed"):
            if key in evidence:
                result[key] = evidence[key]
        return result

    def _copy_dict(self, value: dict | None) -> dict | None:
        return dict(value) if value else None
