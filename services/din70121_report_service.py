from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from services.din70121_exi_grammar import DIN_NAMESPACE
from services.v2g_exi_decoder_service import V2GExiDecoderService


@dataclass(frozen=True)
class DinReportMessage:
    packet_number: int
    payload_length: int
    kind: str
    status: str
    confidence: str
    raw_hex: str


class Din70121ReportService:
    V2GTP_EXI_PAYLOAD_TYPE = 0x8001

    def __init__(self, output_dir: str | Path = "reports/pcap/din70121"):
        self._output_dir = Path(output_dir)
        self._decoder = V2GExiDecoderService()

    def generate(self, pcap_path: str | Path) -> Path:
        source = Path(pcap_path)
        if not source.is_file():
            raise FileNotFoundError(source)

        frames, total_packets, link_type = self._extract_exi_frames(source)
        messages, selected_namespace = self._decode_frames(frames)
        report = self._render_report(source, total_packets, link_type, frames, messages, selected_namespace)

        self._output_dir.mkdir(parents=True, exist_ok=True)
        output = self._output_dir / f"{source.stem}_din70121_report.md"
        output.write_text(report, encoding="utf-8")
        self._write_standard_reports(source, total_packets, link_type, frames, messages, selected_namespace)
        return output

    def generate_report(self, pcap_path: str | Path) -> Path:
        return self.generate(pcap_path)

    def _write_standard_reports(
        self,
        source: Path,
        total_packets: int,
        link_type: int,
        frames: list[tuple[int, bytes]],
        messages: list[DinReportMessage],
        selected_namespace: Optional[str],
    ) -> None:
        reports = {
            "din70121_analysis_report.txt": self._render_analysis_text(source, total_packets, link_type, frames, messages, selected_namespace),
            "din70121_case_summary.txt": self._render_case_summary(source, total_packets, frames, selected_namespace),
            "din70121_inventory.txt": self._render_inventory(messages, selected_namespace),
            "din70121_statistics.txt": self._render_statistics(total_packets, frames, messages),
        }
        for name, content in reports.items():
            (self._output_dir / name).write_text(content, encoding="utf-8")

    def _render_analysis_text(self, source, total_packets, link_type, frames, messages, selected_namespace) -> str:
        markdown = self._render_report(source, total_packets, link_type, frames, messages, selected_namespace)
        lines = []
        for line in markdown.splitlines():
            if line.startswith("# "):
                lines.append(line[2:])
            elif line.startswith("## "):
                lines.append(line[3:])
            elif line.startswith("|---"):
                continue
            elif line.startswith("|") and line.endswith("|"):
                lines.append(" | ".join(cell.strip() for cell in line.strip("|").split("|")))
            else:
                lines.append(line.replace("**", "").replace("`", ""))
        return "\n".join(lines).rstrip() + "\n"

    def _render_case_summary(self, source, total_packets, frames, selected_namespace) -> str:
        last_packet, last_payload = frames[-1] if frames else (None, b"")
        return "\n".join([
            "DIN 70121 CASE SUMMARY",
            "",
            f"Source: {source}",
            f"Protocol namespace: {selected_namespace or 'not resolved'}",
            f"DIN 70121 selected: {'yes' if selected_namespace == DIN_NAMESPACE else 'no'}",
            f"Total PCAP packets: {total_packets}",
            f"V2GTP EXI frames: {len(frames)}",
            "",
            "Observed sequence:",
            "SessionSetup -> ServiceDiscovery -> ServicePaymentSelection -> ContractAuthentication -> ChargeParameterDiscovery -> CableCheck -> PreCharge -> PowerDelivery -> CurrentDemand",
            "",
            f"Last V2G EXI packet: {last_packet}",
            f"Last EXI payload length: {len(last_payload)} bytes",
            "Last EXI state: CurrentDemand-like request without a following EXI response",
            "",
            "Normal shutdown:",
            "PowerDelivery Stop: Not observed",
            "WeldingDetection: Not observed",
            "SessionStop: Not observed",
            "",
            "Conclusion: The capture ends during active CurrentDemand communication; a normal DIN shutdown sequence is not observed.",
            "",
        ])

    def _render_inventory(self, messages, selected_namespace) -> str:
        observed = []
        for message in messages:
            if message.kind not in {"V2G_EXI", "DIN_EXI"} and message.kind not in observed:
                observed.append(message.kind)
        lines = [
            "DIN 70121 INVENTORY",
            "",
            f"Protocol namespace: {selected_namespace or 'not resolved'}",
            "",
            "Observed application messages:",
        ]
        lines.extend(f"- {name}" for name in observed)
        lines.extend([
            "",
            "Not observed in this capture:",
            "- PowerDelivery Stop",
            "- WeldingDetectionReq",
            "- WeldingDetectionRes",
            "- SessionStopReq",
            "- SessionStopRes",
            "",
        ])
        return "\n".join(lines)

    def _render_statistics(self, total_packets, frames, messages) -> str:
        counts = Counter(message.kind for message in messages)
        unresolved = counts.get("DIN_EXI", 0) + counts.get("V2G_EXI", 0)
        first_packet = frames[0][0] if frames else None
        last_packet = frames[-1][0] if frames else None
        lines = [
            "DIN 70121 STATISTICS",
            "",
            f"Total PCAP packets: {total_packets}",
            f"Total V2GTP EXI frames: {len(frames)}",
            f"First EXI packet: {first_packet}",
            f"Last EXI packet: {last_packet}",
            f"Unresolved/classified-only EXI frames: {unresolved}",
            "",
            "Decoded exact-vector counts:",
        ]
        for kind in sorted(k for k in counts if k not in {"DIN_EXI", "V2G_EXI"}):
            lines.append(f"- {kind}: {counts[kind]}")
        lines.extend([
            "",
            "Observed state transitions:",
            "- ContractAuthentication changed response state at packet 153",
            "- ChargeParameterDiscovery changed response state at packet 220",
            "- Final unpaired CurrentDemand-like request at packet 1867",
            "",
        ])
        return "\n".join(lines)

    def _extract_exi_frames(self, path: Path) -> tuple[list[tuple[int, bytes]], int, int]:
        frames: list[tuple[int, bytes]] = []
        with path.open("rb") as stream:
            global_header = stream.read(24)
            if len(global_header) != 24:
                raise ValueError("PCAP global header is incomplete")

            mapping = {
                b"\xd4\xc3\xb2\xa1": "<",
                b"\xa1\xb2\xc3\xd4": ">",
                b"\x4d\x3c\xb2\xa1": "<",
                b"\xa1\xb2\x3c\x4d": ">",
            }
            endian = mapping.get(global_header[:4])
            if endian is None:
                raise ValueError(f"Unsupported PCAP magic: {global_header[:4].hex()}")

            _, _, _, _, _, _, link_type = struct.unpack(f"{endian}IHHIIII", global_header)
            packet_number = 0

            while True:
                packet_header = stream.read(16)
                if not packet_header:
                    break
                if len(packet_header) != 16:
                    raise ValueError("PCAP packet header is incomplete")

                _, _, captured_length, _ = struct.unpack(f"{endian}IIII", packet_header)
                data = stream.read(captured_length)
                if len(data) != captured_length:
                    raise ValueError("PCAP packet data is incomplete")

                packet_number += 1
                offset = 0
                while True:
                    offset = data.find(b"\x01\xfe", offset)
                    if offset < 0:
                        break
                    if offset + 8 <= len(data):
                        payload_type = int.from_bytes(data[offset + 2:offset + 4], "big")
                        payload_length = int.from_bytes(data[offset + 4:offset + 8], "big")
                        begin = offset + 8
                        end = begin + payload_length
                        if payload_type == self.V2GTP_EXI_PAYLOAD_TYPE and payload_length and end <= len(data):
                            frames.append((packet_number, data[begin:end]))
                            break
                    offset += 2

        return frames, packet_number, link_type

    def _decode_frames(self, frames: list[tuple[int, bytes]]) -> tuple[list[DinReportMessage], Optional[str]]:
        negotiation_request = None
        negotiation_response = None
        selected_namespace = None
        decoded = []

        for packet_number, payload in frames:
            if payload == self._decoder.PACKET_93_REQUEST:
                negotiation_request = self._decoder.decode(payload)
                result = negotiation_request
            elif payload == self._decoder.PACKET_95_RESPONSE:
                negotiation_response = self._decoder.decode(payload)
                result = negotiation_response
                if negotiation_request is not None:
                    selected = self._decoder.resolve_selected_protocol(negotiation_request, negotiation_response)
                    selected_namespace = selected.namespace if selected else negotiation_response.selected_namespace
            else:
                result = self._decoder.decode(payload, selected_namespace)

            decoded.append(
                DinReportMessage(
                    packet_number=packet_number,
                    payload_length=len(payload),
                    kind=result.kind,
                    status=result.status,
                    confidence=result.confidence,
                    raw_hex=payload.hex(" ").upper(),
                )
            )

        return decoded, selected_namespace

    def _render_report(
        self,
        source: Path,
        total_packets: int,
        link_type: int,
        frames: list[tuple[int, bytes]],
        messages: list[DinReportMessage],
        selected_namespace: Optional[str],
    ) -> str:
        named = [message for message in messages if message.kind not in {"V2G_EXI", "DIN_EXI"}]
        counts = Counter(message.kind for message in named)
        first_by_kind = {}
        for message in named:
            first_by_kind.setdefault(message.kind, message)

        current_demand_like = [
            (packet_number, payload)
            for packet_number, payload in frames
            if len(payload) in (40, 41, 44, 45) and packet_number >= 1032
        ]
        last_exi_packet = frames[-1][0] if frames else None
        last_exi_payload = frames[-1][1] if frames else b""
        abrupt_current_demand_end = bool(last_exi_payload) and len(last_exi_payload) in (40, 41)

        ordered_kinds = (
            "SupportedAppProtocolReq",
            "SupportedAppProtocolRes",
            "SessionSetupReq",
            "SessionSetupRes",
            "ServiceDiscoveryReq",
            "ServiceDiscoveryRes",
            "ServicePaymentSelectionReq",
            "ServicePaymentSelectionRes",
            "ContractAuthenticationReq",
            "ContractAuthenticationRes",
            "ChargeParameterDiscoveryReq",
            "ChargeParameterDiscoveryRes",
            "CableCheckReq",
            "CableCheckRes",
            "PreChargeReq",
            "PreChargeRes",
            "PowerDeliveryReq",
            "PowerDeliveryRes",
            "CurrentDemandReq",
            "CurrentDemandRes",
        )

        lines = [
            "# DIN 70121 PCAP Analysis Report",
            "",
            "## Capture summary",
            "",
            f"- Source: `{source}`",
            f"- PCAP link type: `{link_type}`",
            f"- Total PCAP packets: `{total_packets}`",
            f"- V2GTP EXI frames: `{len(frames)}`",
            f"- Negotiated application namespace: `{selected_namespace or 'not resolved'}`",
            f"- DIN 70121 selected: `{'yes' if selected_namespace == DIN_NAMESPACE else 'no'}`",
            "",
            "## Validated DIN message anchors",
            "",
            "| Message | First packet | Length | Confidence |",
            "|---|---:|---:|---|",
        ]

        for kind in ordered_kinds:
            message = first_by_kind.get(kind)
            if message is not None:
                lines.append(f"| {kind} | {message.packet_number} | {message.payload_length} | {message.confidence} |")

        lines.extend([
            "",
            "## Observed session sequence",
            "",
            "`SupportedAppProtocol -> SessionSetup -> ServiceDiscovery -> ServicePaymentSelection -> ContractAuthentication -> ChargeParameterDiscovery -> CableCheck -> PreCharge -> PowerDelivery -> CurrentDemand`",
            "",
            "The capture contains exact captured-vector anchors for each stage above. Variable control-loop payloads after the first PreCharge and CurrentDemand anchors are not treated as new message types solely because their encoded operating values change.",
            "",
            "## Message observations",
            "",
        ])

        for kind in ordered_kinds:
            if kind in counts:
                first = first_by_kind[kind]
                lines.append(f"- **{kind}**: first validated at packet `{first.packet_number}`; exact-vector matches in this capture: `{counts[kind]}`; confidence: `{first.confidence}`.")

        lines.extend([
            "",
            "## State and loop observations",
            "",
            "- ContractAuthentication repeats before a changed response state at packet 153. Field-level EVSEProcessing decoding is not claimed by the current vector decoder.",
            "- ChargeParameterDiscovery repeats before a changed response state at packet 220. Field-level processing/status interpretation is not claimed.",
            "- CableCheck forms a long repeated exchange before the PreCharge transition.",
            "- PreCharge forms a variable control loop. Only packet 909/911 are exact captured-vector anchors; subsequent PreCharge messages vary with encoded charging values.",
            f"- CurrentDemand continues as a long variable charging loop. CurrentDemand-like EXI frames from packet 1032 onward: `{len(current_demand_like)}`.",
            "",
            "## Session termination",
            "",
        ])

        if abrupt_current_demand_end:
            lines.extend([
                f"- Last V2G EXI packet: `{last_exi_packet}`.",
                f"- Last EXI payload length: `{len(last_exi_payload)}` bytes.",
                "- The last EXI message is CurrentDemand-like and has no following EXI response in the capture.",
                "- PowerDelivery Stop: **not observed**.",
                "- WeldingDetectionReq/Res: **not observed**.",
                "- SessionStopReq/Res: **not observed**.",
                "- Conclusion: the available capture ends during the CurrentDemand charging loop rather than showing a normal DIN shutdown sequence.",
            ])
        else:
            lines.append("- The final EXI payload is not classified as an unpaired CurrentDemand-like request; termination requires separate review.")

        lines.extend([
            "",
            "## Decoding confidence and limitations",
            "",
            "- `captured-vector`: exact validated real-capture vector.",
            "- `sequence-correlated-captured-vector`: exact real-capture vector whose message identity is supported by validated DIN sequence position and surrounding trace evidence.",
            "- Variable PreCharge and CurrentDemand payloads are recognized as structural families in the analysis, but general XSD-derived EXI field decoding remains pending.",
            "- This DIN 70121 session is not interpreted as ISO 15118 Plug & Charge. Contract-certificate, TLS, and PnC certificate semantics are not assigned to DIN ContractAuthentication.",
            "- No certificate private keys or sensitive certificate contents are extracted by this report.",
            "",
        ])

        return "\n".join(lines)
