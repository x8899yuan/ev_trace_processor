from pathlib import Path
from typing import Any, Optional

from models.vehicle_software_inventory import VehicleSoftwareInventory


class DltReportService:
    def __init__(self, output_directory: Path = Path("reports") / "dlt") -> None:
        self.output_directory = Path(output_directory)

    def generate(
        self,
        analysis: dict[str, Any],
        inventory: Optional[VehicleSoftwareInventory] = None,
    ) -> dict[str, Path]:
        self._validate_analysis(analysis)
        self.output_directory.mkdir(parents=True, exist_ok=True)

        reports = {
            "inventory": self.output_directory / "dlt_inventory.txt",
            "statistics": self.output_directory / "dlt_statistics.txt",
            "analysis": self.output_directory / "dlt_analysis_report.txt",
            "case_summary": self.output_directory / "dlt_case_summary.txt",
        }

        reports["inventory"].write_text(
            self._build_inventory(analysis, inventory), encoding="utf-8"
        )
        reports["statistics"].write_text(
            self._build_statistics(analysis), encoding="utf-8"
        )
        reports["analysis"].write_text(
            self._build_analysis_report(analysis, inventory), encoding="utf-8"
        )
        reports["case_summary"].write_text(
            self._build_case_summary(analysis, inventory), encoding="utf-8"
        )
        return reports

    def _validate_analysis(self, analysis: dict[str, Any]) -> None:
        required = {
            "capture",
            "source_file_counts",
            "ecu_counts",
            "application_counts",
            "context_counts",
            "application_context_counts",
            "severity_counts",
            "verbosity_counts",
            "keyword_counts",
            "finding_category_counts",
            "critical_findings",
            "error_findings",
            "warning_findings",
            "keyword_observations",
            "finding_signatures",
            "unique_finding_signature_count",
            "timeline",
            "analysis_parameters",
        }
        missing = sorted(required.difference(analysis))
        if missing:
            raise ValueError(
                "DLT analysis is missing required fields: " + ", ".join(missing)
            )

    def _build_inventory(
        self,
        analysis: dict[str, Any],
        inventory: Optional[VehicleSoftwareInventory],
    ) -> str:
        capture = analysis["capture"]
        lines = [
            "DLT INVENTORY",
            "",
            f"Trace files: {capture['trace_count']}",
            f"Events analyzed: {capture['event_count']:,}",
            f"Start timestamp: {self._format_value(capture['start_timestamp'])}",
            f"End timestamp: {self._format_value(capture['end_timestamp'])}",
            f"Duration: {capture['duration_seconds']:.6f} seconds",
            "",
            "Source files",
        ]
        lines.extend(
            f"{name}: {count:,} events"
            for name, count in analysis["source_file_counts"].items()
        )
        lines.extend(["", "ECUs"])
        lines.extend(
            f"{ecu}: {count:,} events"
            for ecu, count in analysis["ecu_counts"].items()
        )
        self._append_software_inventory(lines, inventory, detailed=True)
        lines.extend(["", "Top applications"])
        lines.extend(
            f"{name}: {count:,} events"
            for name, count in analysis["application_counts"].items()
        )
        lines.extend(["", "Top contexts"])
        lines.extend(
            f"{name}: {count:,} events"
            for name, count in analysis["context_counts"].items()
        )
        return "\n".join(lines) + "\n"

    def _build_statistics(self, analysis: dict[str, Any]) -> str:
        lines = ["DLT STATISTICS", "", "Severity distribution"]
        lines.extend(
            f"{severity}: {count:,}"
            for severity, count in analysis["severity_counts"].items()
        )
        lines.extend(["", "Verbosity distribution"])
        lines.extend(
            f"{name}: {count:,}"
            for name, count in analysis["verbosity_counts"].items()
        )
        lines.extend(["", "Finding categories"])
        lines.extend(
            f"{name}: {count:,}"
            for name, count in analysis["finding_category_counts"].items()
        )
        lines.append(
            f"Unique normalized finding signatures: "
            f"{analysis['unique_finding_signature_count']:,}"
        )
        lines.extend(["", "Keyword observations"])
        lines.extend(
            f"{term}: {count:,}"
            for term, count in analysis["keyword_counts"].items()
        )
        lines.extend(["", "Top application/context combinations"])
        lines.extend(
            f"{item['application_id']}.{item['context_id']}: "
            f"{item['event_count']:,} events"
            for item in analysis["application_context_counts"]
        )
        lines.extend(["", "Timeline"])
        for row in analysis["timeline"]:
            lines.append(
                f"{self._format_value(row['start_timestamp'])} to "
                f"{self._format_value(row['end_timestamp'])} | "
                f"events={row['event_count']:,} | "
                f"severity={self._inline_counts(row['severity_counts'])} | "
                f"findings={self._inline_counts(row['finding_counts'])}"
            )
        return "\n".join(lines) + "\n"

    def _build_analysis_report(
        self,
        analysis: dict[str, Any],
        inventory: Optional[VehicleSoftwareInventory],
    ) -> str:
        capture = analysis["capture"]
        severity = analysis["severity_counts"]
        categories = analysis["finding_category_counts"]
        lines = [
            "DLT ANALYSIS REPORT",
            "",
            "Capture overview",
            f"Trace files: {capture['trace_count']}",
            f"Events analyzed: {capture['event_count']:,}",
            f"Start: {self._format_value(capture['start_timestamp'])}",
            f"End: {self._format_value(capture['end_timestamp'])}",
            f"Duration: {capture['duration_seconds']:.6f} seconds",
        ]
        self._append_software_inventory(lines, inventory, detailed=False)
        lines.extend(
            [
                "",
                "Severity summary",
                f"FATAL: {severity.get('FATAL', 0):,}",
                f"ERROR: {severity.get('ERROR', 0):,}",
                f"WARN: {severity.get('WARN', 0):,}",
                f"INFO: {severity.get('INFO', 0):,}",
                "",
                "Finding classification",
                f"Critical findings: {categories.get('critical', 0):,}",
                f"Error findings: {categories.get('error', 0):,}",
                f"Warning findings: {categories.get('warning', 0):,}",
                f"Keyword observations at other severities: "
                f"{categories.get('keyword_observation', 0):,}",
                f"Unique normalized finding signatures: "
                f"{analysis['unique_finding_signature_count']:,}",
                "",
                "Critical findings",
            ]
        )
        self._append_examples(lines, analysis["critical_findings"], "None")
        lines.extend(["", "Top repeated finding signatures"])
        if analysis["finding_signatures"]:
            for item in analysis["finding_signatures"]:
                lines.extend(
                    [
                        f"[{item['category'].upper()}] {item['source_file']} | "
                        f"ECU={item['ecu_id']} | "
                        f"{item['application_id']}.{item['context_id']}",
                        f"Occurrences: {item['occurrence_count']:,}",
                        f"First: {self._format_value(item['first_timestamp'])}",
                        f"Last: {self._format_value(item['last_timestamp'])}",
                        f"Signature: {item['signature']}",
                        f"Example: {item['example_message']}",
                        "",
                    ]
                )
        else:
            lines.append("None")
        lines.extend(["Diagnostic observations", self._finding_summary(analysis)])
        lines.extend(
            [
                "",
                "Interpretation limitations",
                "Severity reflects DLT message metadata. Keyword observations identify "
                "text patterns only and are not equivalent to faults. Repeated messages "
                "are consolidated into normalized signatures. Software inventory contains "
                "only values explicitly observed in the analyzed DLT sample and does not "
                "represent complete vehicle configuration. The report does not assign root "
                "cause solely from message text, filename, repetition count, application/"
                "context name, keyword occurrence, or software-version evidence.",
            ]
        )
        return "\n".join(lines) + "\n"

    def _build_case_summary(
        self,
        analysis: dict[str, Any],
        inventory: Optional[VehicleSoftwareInventory],
    ) -> str:
        capture = analysis["capture"]
        severity = analysis["severity_counts"]
        categories = analysis["finding_category_counts"]
        lines = [
            "DLT CASE SUMMARY",
            "",
            f"Trace files analyzed: {capture['trace_count']}",
            f"Events analyzed: {capture['event_count']:,}",
            f"ECUs: {self._inline_counts(analysis['ecu_counts'])}",
            f"FATAL records: {severity.get('FATAL', 0):,}",
            f"ERROR records: {severity.get('ERROR', 0):,}",
            f"WARN records: {severity.get('WARN', 0):,}",
            f"Keyword observations at other severities: "
            f"{categories.get('keyword_observation', 0):,}",
            f"Unique normalized finding signatures: "
            f"{analysis['unique_finding_signature_count']:,}",
        ]
        self._append_inventory_summary(lines, inventory)
        if analysis["critical_findings"]:
            critical = analysis["critical_findings"][0]
            lines.extend(
                [
                    "",
                    "Critical observation",
                    f"Timestamp: {self._format_value(critical['timestamp'])}",
                    f"Source: {critical['source_file']}",
                    f"ECU: {critical['ecu_id']}",
                    f"Application/context: "
                    f"{critical['application_id']}.{critical['context_id']}",
                    f"Message: {critical['message']}",
                ]
            )
        lines.extend(["", "Top repeated signatures"])
        for item in analysis["finding_signatures"][:5]:
            lines.append(
                f"{item['occurrence_count']:,}x | {item['category']} | "
                f"{item['application_id']}.{item['context_id']} | "
                f"{item['signature']}"
            )
        lines.extend(
            [
                "",
                "Finding",
                self._finding_summary(analysis),
                "",
                "Limitation",
                "This summary reports observed DLT severity, repeated log signatures, "
                "and software evidence from the analyzed ICAS1 DLT sample. It does not "
                "by itself establish complete vehicle identity, complete ECU software "
                "inventory, causal relationships between components, or a vehicle-level "
                "root cause.",
            ]
        )
        return "\n".join(lines) + "\n"

    def _append_software_inventory(
        self,
        lines: list[str],
        inventory: Optional[VehicleSoftwareInventory],
        detailed: bool,
    ) -> None:
        lines.extend(["", "Vehicle / software inventory"])
        if inventory is None:
            lines.append("Not provided")
            return

        vehicle = inventory.vehicle
        lines.extend(
            [
                f"VIN: {vehicle.vin or 'Not identified from DLT'}",
                f"Vehicle identifier: "
                f"{vehicle.vehicle_identifier or 'Not identified from DLT'}",
                f"Model: {vehicle.model or 'Not identified from DLT'}",
                f"Model year: {vehicle.model_year or 'Not identified from DLT'}",
                "",
                "ICAS1 software components",
            ]
        )
        if not inventory.ecus:
            lines.append("None identified")
            return

        for ecu in inventory.ecus:
            lines.append(
                f"{ecu.name or 'Unknown component'} / ECU "
                f"{ecu.ecu_id or 'Not identified'}"
            )
            lines.append(
                f"  Platform/software identifier: "
                f"{ecu.platform_version or 'Not identified'}"
            )
            if ecu.software_part_number:
                lines.append(f"  Software part number: {ecu.software_part_number}")
            if ecu.hardware_part_number:
                lines.append(f"  Hardware part number: {ecu.hardware_part_number}")
            if ecu.hardware_version:
                lines.append(f"  Hardware version: {ecu.hardware_version}")
            if ecu.bootloader_version:
                lines.append(f"  Bootloader version: {ecu.bootloader_version}")
            if ecu.dataset_version:
                lines.append(f"  Dataset version: {ecu.dataset_version}")

            if detailed and ecu.software_clusters:
                lines.append("  Software clusters:")
                for cluster in ecu.software_clusters:
                    lines.append(
                        f"    {cluster.name}: {cluster.version or 'Not identified'}"
                    )

            if ecu.software_components:
                lines.append("  Applications/components:")
                components = ecu.software_components if detailed else ecu.software_components[:10]
                for component in components:
                    fields = []
                    if component.version:
                        fields.append(f"version={component.version}")
                    if component.release:
                        fields.append(f"release={component.release}")
                    if component.profile:
                        fields.append(f"profile={component.profile}")
                    if component.build:
                        fields.append(f"build={component.build}")
                    if component.hash_value:
                        fields.append(f"hash={component.hash_value}")
                    suffix = ", ".join(fields) if fields else "version not identified"
                    lines.append(f"    {component.name}: {suffix}")

    def _append_inventory_summary(
        self,
        lines: list[str],
        inventory: Optional[VehicleSoftwareInventory],
    ) -> None:
        if inventory is None:
            return
        lines.extend(["", "ICAS1 software summary"])
        for ecu in inventory.ecus:
            lines.append(
                f"{ecu.name or 'Unknown component'} / ECU "
                f"{ecu.ecu_id or 'Not identified'}: "
                f"{ecu.platform_version or 'platform version not identified'}"
            )

    def _append_examples(
        self,
        lines: list[str],
        findings: list[dict[str, Any]],
        empty_text: str,
    ) -> None:
        if not findings:
            lines.append(empty_text)
            return
        for item in findings:
            lines.append(
                f"{self._format_value(item['timestamp'])} | {item['source_file']} | "
                f"ECU={item['ecu_id']} | "
                f"{item['application_id']}.{item['context_id']} | "
                f"{item['message']}"
            )

    def _finding_summary(self, analysis: dict[str, Any]) -> str:
        critical = analysis["critical_findings"]
        signatures = analysis["finding_signatures"]
        parts = []
        if critical:
            item = critical[0]
            parts.append(
                f"A FATAL DLT record was observed in "
                f"{item['application_id']}.{item['context_id']}: "
                f"{item['message']}."
            )
        if signatures:
            top = signatures[0]
            parts.append(
                "The most frequently repeated normalized finding in the analyzed "
                f"sample occurred {top['occurrence_count']:,} times in "
                f"{top['application_id']}.{top['context_id']}."
            )
        reset = next(
            (
                item
                for item in signatures
                if item["signature"]
                == "[res][poweron restart][past reset]: printing reset reason.."
            ),
            None,
        )
        if reset:
            parts.append(
                "R7 RESM.ERR contains reset-related evidence with "
                f"{reset['occurrence_count']:,} occurrences of the normalized "
                "past-reset signature."
            )
        if not parts:
            return "No classified DLT finding was available in the analyzed sample."
        return " ".join(parts)

    def _inline_counts(self, counts: dict[Any, int]) -> str:
        if not counts:
            return "None"
        return ", ".join(f"{key}={value:,}" for key, value in counts.items())

    def _format_value(self, value: Any) -> str:
        if value is None:
            return "None"
        if hasattr(value, "isoformat"):
            return value.isoformat()
        return str(value)
