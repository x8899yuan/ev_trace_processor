from pathlib import Path
from typing import Any


class PcapReportService:
    def __init__(self, output_directory: Path = Path("reports") / "pcap") -> None:
        self.output_directory = Path(output_directory)

    def generate(self, analysis: dict[str, Any]) -> dict[str, Path]:
        self._validate_analysis(analysis)
        self.output_directory.mkdir(parents=True, exist_ok=True)

        reports = {
            "inventory": self.output_directory / "pcap_inventory.txt",
            "statistics": self.output_directory / "pcap_statistics.txt",
            "analysis": self.output_directory / "pcap_analysis_report.txt",
            "case_summary": self.output_directory / "pcap_case_summary.txt",
        }

        reports["inventory"].write_text(
            self._build_inventory(analysis),
            encoding="utf-8",
        )
        reports["statistics"].write_text(
            self._build_statistics(analysis),
            encoding="utf-8",
        )
        reports["analysis"].write_text(
            self._build_analysis_report(analysis),
            encoding="utf-8",
        )
        reports["case_summary"].write_text(
            self._build_case_summary(analysis),
            encoding="utf-8",
        )

        return reports

    def _validate_analysis(self, analysis: dict[str, Any]) -> None:
        required = {
            "capture",
            "protocol_counts",
            "ether_type_counts",
            "mac_pairs",
            "frame_size_counts",
            "payload_size_counts",
            "vlan_counts",
            "timeline",
            "transition_analysis",
            "analysis_parameters",
        }
        missing = sorted(required.difference(analysis))

        if missing:
            raise ValueError(
                "PCAP analysis is missing required fields: "
                + ", ".join(missing)
            )

    def _build_inventory(self, analysis: dict[str, Any]) -> str:
        capture = analysis["capture"]
        lines = [
            "PCAP INVENTORY",
            "",
            f"File: {capture['file_name']}",
            f"Path: {capture['file_path']}",
            f"File size: {capture['file_size_bytes']:,} bytes",
            f"Packet count: {capture['packet_count']:,}",
            f"Captured bytes: {capture['captured_bytes']:,}",
            f"Start timestamp: {self._format_value(capture['start_timestamp'])}",
            f"End timestamp: {self._format_value(capture['end_timestamp'])}",
            f"Duration: {capture['duration_seconds']:.6f} seconds",
            "",
            "Protocols",
        ]

        lines.extend(
            f"{protocol}: {count:,}"
            for protocol, count in analysis["protocol_counts"].items()
        )

        lines.extend(["", "EtherTypes"])
        lines.extend(
            f"{ether_type}: {count:,}"
            for ether_type, count in analysis["ether_type_counts"].items()
        )

        lines.extend(["", "MAC communication pairs"])

        if analysis["mac_pairs"]:
            lines.extend(
                f"{item['src_mac']} -> {item['dst_mac']}: "
                f"{item['packet_count']:,} packets"
                for item in analysis["mac_pairs"]
            )
        else:
            lines.append("None")

        lines.extend(["", "VLANs"])

        if analysis["vlan_counts"]:
            lines.extend(
                f"VLAN {vlan_id}: {count:,} packets"
                for vlan_id, count in analysis["vlan_counts"].items()
            )
        else:
            lines.append("None identified")

        return "\n".join(lines) + "\n"

    def _build_statistics(self, analysis: dict[str, Any]) -> str:
        lines = [
            "PCAP STATISTICS",
            "",
            "Frame-size distribution",
        ]

        lines.extend(
            f"{size} bytes: {count:,} packets"
            for size, count in analysis["frame_size_counts"].items()
        )

        lines.extend(["", "Payload-size distribution"])
        lines.extend(
            f"{size} bytes: {count:,} packets"
            for size, count in analysis["payload_size_counts"].items()
        )

        parameters = analysis["analysis_parameters"]
        lines.extend(
            [
                "",
                "Timeline parameters",
                f"Bin size: {parameters['bin_seconds']} seconds",
                f"Baseline bins: {parameters['baseline_bins']}",
                f"Change factor: {parameters['change_factor']}",
                "",
                "Timeline",
            ]
        )

        for row in analysis["timeline"]:
            sizes = ", ".join(
                f"{size}:{count}"
                for size, count in row["frame_size_counts"].items()
            )
            lines.append(
                f"{self._format_value(row['start_timestamp'])} to "
                f"{self._format_value(row['end_timestamp'])} | "
                f"packets={row['packet_count']:,} | "
                f"bytes={row['captured_bytes']:,} | "
                f"frame_sizes={sizes}"
            )

        return "\n".join(lines) + "\n"

    def _build_analysis_report(self, analysis: dict[str, Any]) -> str:
        capture = analysis["capture"]
        transition = analysis["transition_analysis"]
        primary = transition.get("primary_period")
        lines = [
            "PCAP ANALYSIS REPORT",
            "",
            "Capture overview",
            f"File: {capture['file_name']}",
            f"Packets: {capture['packet_count']:,}",
            f"Start: {self._format_value(capture['start_timestamp'])}",
            f"End: {self._format_value(capture['end_timestamp'])}",
            f"Duration: {capture['duration_seconds']:.6f} seconds",
            "",
            "Protocol identification",
        ]

        lines.extend(
            f"{protocol}: {count:,} packets"
            for protocol, count in analysis["protocol_counts"].items()
        )

        lines.extend(["", "Communication topology"])
        lines.extend(
            f"{item['src_mac']} -> {item['dst_mac']}: "
            f"{item['packet_count']:,} packets"
            for item in analysis["mac_pairs"]
        )

        lines.extend(["", "Dominant frame sizes"])
        lines.extend(
            f"{size} bytes: {count:,} packets"
            for size, count in list(analysis["frame_size_counts"].items())[:10]
        )

        lines.extend(["", "Transition analysis"])

        if not transition["detected"] or primary is None:
            lines.append("No elevated traffic period met the configured threshold.")
        else:
            lines.extend(
                [
                    f"Baseline: {transition['baseline_packets_per_bin']:.3f} packets/bin",
                    f"Threshold: {transition['threshold_packets_per_bin']:.3f} packets/bin",
                    f"Peak: {transition['peak_packets_per_bin']:,} packets/bin",
                    f"Primary elevated-period start: {self._format_value(primary['start_timestamp'])}",
                    f"Primary elevated-period end: {self._format_value(primary['end_timestamp'])}",
                    f"Primary elevated-period packets: {primary['packet_count']:,}",
                    f"Pre-transition median: {self._format_number(primary['pre_transition_packets_per_bin'])} packets/bin",
                    f"Transition average: {self._format_number(primary['transition_packets_per_bin'])} packets/bin",
                    f"Post-transition median: {self._format_number(primary['post_transition_packets_per_bin'])} packets/bin",
                    f"Post-transition rate reduction vs baseline: {abs(primary['post_vs_baseline_change_percent']):.2f}%",
                    "",
                    "Transition-prominent frame sizes",
                ]
            )

            prominent = primary["prominent_transition_frame_sizes"]

            if prominent:
                for item in prominent:
                    lines.append(
                        f"{item['frame_size']} bytes: "
                        f"{item['transition_count']:,} transition packets, "
                        f"transition share={item['transition_share']:.2%}, "
                        f"baseline share={item['baseline_share']:.2%}, "
                        f"post share={item['post_share']:.2%}"
                    )
            else:
                lines.append("None")

        lines.extend(
            [
                "",
                "Evidence-based findings",
                self._finding_text(analysis),
                "",
                "Interpretation limitations",
                "The report describes observable traffic behavior and protocol/frame characteristics. It does not infer a physical power-loss cause, ECU fault, or HomePlug message semantics from the filename or undocumented payload fields.",
            ]
        )

        return "\n".join(lines) + "\n"

    def _build_case_summary(self, analysis: dict[str, Any]) -> str:
        capture = analysis["capture"]
        transition = analysis["transition_analysis"]
        primary = transition.get("primary_period")
        lines = [
            "PCAP CASE SUMMARY",
            "",
            f"File: {capture['file_name']}",
            f"Packets analyzed: {capture['packet_count']:,}",
            f"Capture duration: {capture['duration_seconds']:.6f} seconds",
            f"Protocols: {self._inline_counts(analysis['protocol_counts'])}",
            f"EtherTypes: {self._inline_counts(analysis['ether_type_counts'])}",
        ]

        if primary is None:
            lines.extend(
                [
                    "Transition detected: No",
                    "Finding: No elevated traffic period met the configured transition threshold.",
                ]
            )
        else:
            prominent_sizes = ", ".join(
                str(item["frame_size"])
                for item in primary["prominent_transition_frame_sizes"]
            ) or "None"
            lines.extend(
                [
                    "Transition detected: Yes",
                    f"Elevated-period start: {self._format_value(primary['start_timestamp'])}",
                    f"Elevated-period end: {self._format_value(primary['end_timestamp'])}",
                    f"Baseline rate: {transition['baseline_packets_per_bin']:.3f} packets/bin",
                    f"Transition rate: {self._format_number(primary['transition_packets_per_bin'])} packets/bin",
                    f"Post-transition rate: {self._format_number(primary['post_transition_packets_per_bin'])} packets/bin",
                    f"Post-transition rate reduction vs baseline: {abs(primary['post_vs_baseline_change_percent']):.2f}%",
                    f"Transition-prominent frame sizes: {prominent_sizes}",
                    "Finding: A measurable elevated traffic interval is followed by a lower persistent packet rate. The report does not assign a physical cause to this transition.",
                ]
            )

        return "\n".join(lines) + "\n"

    def _finding_text(self, analysis: dict[str, Any]) -> str:
        transition = analysis["transition_analysis"]
        primary = transition.get("primary_period")

        if not transition["detected"] or primary is None:
            return "No elevated traffic period met the configured transition threshold."

        prominent_sizes = [
            str(item["frame_size"])
            for item in primary["prominent_transition_frame_sizes"]
        ]
        frame_text = ", ".join(prominent_sizes) if prominent_sizes else "none"

        return (
            "The capture contains a quantitatively distinct elevated traffic period. "
            f"Frame sizes disproportionately represented during that period: {frame_text}. "
            f"The median post-transition packet rate is "
            f"{abs(primary['post_vs_baseline_change_percent']):.2f}% lower than the baseline."
        )

    def _inline_counts(self, counts: dict[Any, int]) -> str:
        if not counts:
            return "None"

        return ", ".join(
            f"{key}={value:,}"
            for key, value in counts.items()
        )

    def _format_value(self, value: Any) -> str:
        if value is None:
            return "None"

        if hasattr(value, "isoformat"):
            return value.isoformat()

        return str(value)

    def _format_number(self, value: Any) -> str:
        if value is None:
            return "None"

        return f"{float(value):.3f}"

    def _format_percent(self, value: Any) -> str:
        if value is None:
            return "None"

        return f"{float(value):.2f}%"
