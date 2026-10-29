from datetime import datetime, timezone
from pathlib import Path
from socket import AF_INET, AF_INET6, inet_ntop
from typing import Any

import dpkt

from models.processed_trace import ProcessedTrace
from models.trace_event import TraceEvent
from models.trace_metadata import TraceMetadata
from readers.base_reader import BaseReader


class PcapReader(BaseReader):
    SUPPORTED_EXTENSION = ".pcap"

    def supports(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == self.SUPPORTED_EXTENSION

    def read(self, file_path: Path) -> ProcessedTrace:
        if not self.supports(file_path):
            raise ValueError(f"Unsupported PCAP file extension: {file_path.suffix}")

        if not file_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        metadata = TraceMetadata(
            file_path=file_path,
            trace_type="PCAP",
            file_size_bytes=file_path.stat().st_size,
        )
        events = []

        with file_path.open("rb") as file:
            reader = dpkt.pcap.Reader(file)
            for timestamp, buffer in reader:
                event_name, payload = self._decode_packet(buffer)
                events.append(
                    TraceEvent(
                        timestamp=datetime.fromtimestamp(float(timestamp), tz=timezone.utc),
                        source_type="PCAP",
                        event_name=event_name,
                        payload=payload,
                    )
                )

        return ProcessedTrace(metadata=metadata, events=events)

    def _decode_packet(self, buffer: bytes) -> tuple[str, dict[str, Any]]:
        payload: dict[str, Any] = {
            "raw_data": bytes(buffer),
            "captured_length": len(buffer),
        }

        try:
            ethernet = dpkt.ethernet.Ethernet(buffer)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
            payload["protocol"] = "UNKNOWN"
            payload["decode_status"] = "invalid_ethernet"
            return "packet", payload

        payload["src_mac"] = self._format_mac(ethernet.src)
        payload["dst_mac"] = self._format_mac(ethernet.dst)
        payload["ether_type"] = ethernet.type

        vlan_ids = self._extract_vlan_ids(ethernet)
        if vlan_ids:
            payload["vlan_ids"] = vlan_ids

        network_data = ethernet.data

        if isinstance(network_data, dpkt.arp.ARP):
            self._decode_arp(network_data, payload)
            return "ARP", payload

        if isinstance(network_data, dpkt.ip.IP):
            return self._decode_ipv4(network_data, payload)

        if isinstance(network_data, dpkt.ip6.IP6):
            return self._decode_ipv6(network_data, payload)

        payload["protocol"] = "ETHERNET"
        return "Ethernet", payload

    def _decode_arp(self, packet: dpkt.arp.ARP, payload: dict[str, Any]) -> None:
        payload["protocol"] = "ARP"
        payload["arp_operation"] = packet.op

        try:
            payload["src_ip"] = inet_ntop(AF_INET, packet.spa)
            payload["dst_ip"] = inet_ntop(AF_INET, packet.tpa)
        except (OSError, ValueError):
            pass

        payload["arp_src_mac"] = self._format_mac(packet.sha)
        payload["arp_dst_mac"] = self._format_mac(packet.tha)

    def _decode_ipv4(
        self,
        packet: dpkt.ip.IP,
        payload: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        payload["network_protocol"] = "IPv4"

        try:
            payload["src_ip"] = inet_ntop(AF_INET, packet.src)
            payload["dst_ip"] = inet_ntop(AF_INET, packet.dst)
        except (OSError, ValueError):
            pass

        payload["ip_protocol_number"] = packet.p
        payload["ttl"] = packet.ttl
        return self._decode_transport(packet.data, payload)

    def _decode_ipv6(
        self,
        packet: dpkt.ip6.IP6,
        payload: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        payload["network_protocol"] = "IPv6"

        try:
            payload["src_ip"] = inet_ntop(AF_INET6, packet.src)
            payload["dst_ip"] = inet_ntop(AF_INET6, packet.dst)
        except (OSError, ValueError):
            pass

        payload["ip_protocol_number"] = packet.nxt
        payload["hop_limit"] = packet.hlim
        return self._decode_transport(packet.data, payload)

    def _decode_transport(
        self,
        transport: Any,
        payload: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        if isinstance(transport, dpkt.udp.UDP):
            payload["protocol"] = "UDP"
            payload["src_port"] = transport.sport
            payload["dst_port"] = transport.dport
            payload["transport_payload"] = bytes(transport.data)
            payload["transport_payload_length"] = len(transport.data)
            return "UDP", payload

        if isinstance(transport, dpkt.tcp.TCP):
            payload["protocol"] = "TCP"
            payload["src_port"] = transport.sport
            payload["dst_port"] = transport.dport
            payload["tcp_flags"] = transport.flags
            payload["transport_payload"] = bytes(transport.data)
            payload["transport_payload_length"] = len(transport.data)
            return "TCP", payload

        payload["protocol"] = payload["network_protocol"]
        return payload["network_protocol"], payload

    def _extract_vlan_ids(self, ethernet: dpkt.ethernet.Ethernet) -> list[int]:
        vlan_tags = getattr(ethernet, "vlan_tags", None)
        if not vlan_tags:
            return []
        return [tag.id for tag in vlan_tags if hasattr(tag, "id")]

    def _format_mac(self, address: bytes) -> str:
        return ":".join(f"{value:02x}" for value in address)
