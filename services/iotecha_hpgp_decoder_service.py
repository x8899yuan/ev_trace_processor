from hashlib import sha256
from ipaddress import IPv6Address
from pathlib import Path
from typing import Any

from models.processed_trace import ProcessedTrace
from models.trace_event import TraceEvent
from services.iotecha_embedded_frame_classifier import IoTechaEmbeddedFrameClassifier


class IotechaHpgpDecoderService:
    RECORD_CLASSES = {
        b"\x04\x00\x09": "measurement_primary",
        b"\x02\x05\x04": "measurement_secondary",
        b"\x07\x00\x0b": "measurement_status",
        b"\x02\x05\x06": "measurement_primary_variant",
        b"\x02\x01\x93": "measurement_block",
        b"\x00\x00\x1a": "measurement_summary",
        b"\x06\x00\x93": "analyzer_metadata",
    }

    METADATA_SIGNATURE = b"\xff\xff\x05\x06\x00\x93\x00\x07"
    STATUS_SIGNATURE = b"\xff\xff\x05\x07\x00\x0b\x00\x07"
    EMBEDDED_ETHERNET_OFFSET = 106
    HOMEPLUG_ETHERTYPE = 0x88E1
    IPV6_ETHERTYPE = 0x86DD
    VLAN_ETHERTYPES = {0x8100, 0x88A8}
    SUPPORTED_HOMEPLUG_MMV = {0x00, 0x01}
    SLAC_MINIMUM_LENGTHS = {
        0x6064: 19,
        0x6065: 25,
        0x6068: 19,
        0x606C: 52,
        0x606E: 20,
        0x606F: 50,
        0x6070: 19,
        0x6074: 62,
        0x6075: 62,
    }

    def __init__(self) -> None:
        self._embedded_classifier = IoTechaEmbeddedFrameClassifier()

    def decode_trace(self, trace: ProcessedTrace) -> list[dict[str, Any]]:
        if trace.metadata.trace_type != "PCAP":
            raise ValueError("IotechaHpgpDecoderService requires a PCAP trace")
        decoded = []
        for index, event in enumerate(trace.events):
            record = self.decode_event(event, index)
            if record is not None:
                decoded.append(record)
        return decoded

    def decode_event(self, event: TraceEvent, packet_index: int | None = None) -> dict[str, Any] | None:
        if event.source_type != "PCAP":
            return None
        if event.payload.get("protocol") != "HOMEPLUG_AV":
            return None
        data = event.payload.get("ethernet_payload")
        if not isinstance(data, bytes) or len(data) < 24:
            return None
        record_class_bytes = data[16:19]
        record_class = self.RECORD_CLASSES.get(record_class_bytes, "unknown")
        metadata_offsets = self._subrecord_offsets(data, self.METADATA_SIGNATURE)
        status_offsets = self._subrecord_offsets(data, self.STATUS_SIGNATURE)
        metadata = self._extract_metadata(data, metadata_offsets)
        regions = self._recover_regions(data, metadata_offsets, status_offsets)
        embedded_frames = self._recover_embedded_frames(data, metadata_offsets, status_offsets)
        return {
            "packet_index": packet_index,
            "timestamp": event.timestamp.isoformat(),
            "source_file": self._source_file(event),
            "outer_src_mac": event.payload.get("src_mac"),
            "outer_dst_mac": event.payload.get("dst_mac"),
            "payload_length": len(data),
            "container_magic": data[:12].hex(),
            "sequence": data[12],
            "record_class_bytes": record_class_bytes.hex(),
            "record_class": record_class,
            "record_length_field": int.from_bytes(data[18:20], "little"),
            "counter_bytes": data[20:24].hex(),
            "embedded_identifier": self._embedded_identifier(data),
            "metadata": metadata,
            "metadata_subrecord_offsets": metadata_offsets,
            "status_subrecord_offsets": status_offsets,
            "regions": regions,
            "embedded_frames": embedded_frames,
        }

    def summarize(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        class_counts: dict[str, int] = {}
        length_counts: dict[int, int] = {}
        identifiers: dict[str, int] = {}
        analyzer_ids: dict[str, int] = {}
        builds: dict[str, int] = {}
        products: dict[str, int] = {}
        embedded_protocols: dict[str, int] = {}
        embedded_subtypes: dict[str, int] = {}
        embedded_mmtypes: dict[str, int] = {}
        metadata_subrecords = 0
        status_subrecords = 0
        embedded_frame_count = 0
        for record in records:
            record_class = record["record_class"]
            class_counts[record_class] = class_counts.get(record_class, 0) + 1
            length = record["payload_length"]
            length_counts[length] = length_counts.get(length, 0) + 1
            identifier = record.get("embedded_identifier")
            if identifier:
                identifiers[identifier] = identifiers.get(identifier, 0) + 1
            metadata = record.get("metadata", {})
            analyzer_id = metadata.get("analyzer_id")
            build = metadata.get("build")
            product = metadata.get("product")
            if analyzer_id:
                analyzer_ids[analyzer_id] = analyzer_ids.get(analyzer_id, 0) + 1
            if build:
                builds[build] = builds.get(build, 0) + 1
            if product:
                products[product] = products.get(product, 0) + 1
            metadata_subrecords += len(record["metadata_subrecord_offsets"])
            status_subrecords += len(record["status_subrecord_offsets"])
            for frame in record.get("embedded_frames", []):
                embedded_frame_count += 1
                protocol = frame["protocol"]
                embedded_protocols[protocol] = embedded_protocols.get(protocol, 0) + 1
                subtype = frame.get("subtype")
                if subtype:
                    embedded_subtypes[subtype] = embedded_subtypes.get(subtype, 0) + 1
                mmtype = frame.get("mmtype")
                if mmtype:
                    embedded_mmtypes[mmtype] = embedded_mmtypes.get(mmtype, 0) + 1
        return {
            "record_count": len(records),
            "record_class_counts": class_counts,
            "payload_length_counts": length_counts,
            "embedded_identifiers": identifiers,
            "analyzer_ids": analyzer_ids,
            "analyzer_builds": builds,
            "analyzer_products": products,
            "metadata_subrecord_count": metadata_subrecords,
            "status_subrecord_count": status_subrecords,
            "embedded_frame_count": embedded_frame_count,
            "embedded_protocol_counts": embedded_protocols,
            "embedded_subtype_counts": embedded_subtypes,
            "embedded_mmtype_counts": embedded_mmtypes,
        }

    def _recover_embedded_frames(self, data: bytes, metadata_offsets: list[int], status_offsets: list[int]) -> list[dict[str, Any]]:
        offset = self.EMBEDDED_ETHERNET_OFFSET
        candidate = self._validate_embedded_frame(data, offset)
        if candidate is None:
            return []

        if candidate["protocol"] == "ipv6":
            captured_length = candidate["frame_length"]
            captured_data = data[offset:offset + captured_length]
            return [{
                "offset": offset,
                "packet_offset": offset + 14,
                "captured_length": captured_length,
                "boundary_source": "ipv6_payload_length",
                "protocol": "ipv6",
                "subtype": self._ipv6_subtype(candidate["next_header"]),
                "confidence": 1.0,
                "destination_mac": candidate["destination_mac"],
                "source_mac": candidate["source_mac"],
                "ethertype": "0x86DD",
                "ip_version": 6,
                "ipv6_source": candidate["ipv6_source"],
                "ipv6_destination": candidate["ipv6_destination"],
                "ipv6_payload_length": candidate["ipv6_payload_length"],
                "next_header": candidate["next_header"],
                "hop_limit": candidate["hop_limit"],
                "data": captured_data,
                "preview": captured_data[:64].hex(),
                "sha256": self._sha256(captured_data),
            }]

        boundary = self._next_boundary(data, offset, metadata_offsets, status_offsets)
        captured_data = data[offset:boundary]
        classification = self._embedded_classifier.classify(captured_data, offset=offset)
        evidence = {item.pattern: item.value for item in classification.evidence}
        return [{
            "offset": offset,
            "packet_offset": offset + 14,
            "captured_length": len(captured_data),
            "boundary_source": self._boundary_source(boundary, len(data), metadata_offsets, status_offsets),
            "protocol": classification.protocol.value,
            "subtype": classification.subtype,
            "confidence": classification.confidence,
            "destination_mac": evidence.get("destination_mac"),
            "source_mac": evidence.get("source_mac"),
            "ethertype": evidence.get("inner_ethertype") or evidence.get("ethertype"),
            "mmv": evidence.get("homeplug_mmv"),
            "mmtype": evidence.get("homeplug_mmtype"),
            "minimum_message_length": candidate["minimum_message_length"],
            "data": captured_data,
            "preview": captured_data[:64].hex(),
            "sha256": self._sha256(captured_data),
        }]

    def _validate_embedded_frame(self, data: bytes, offset: int) -> dict[str, Any] | None:
        ethernet = self._parse_embedded_ethernet(data, offset)
        if ethernet is None:
            return None

        if ethernet["ethertype"] == self.HOMEPLUG_ETHERTYPE:
            return self._validate_embedded_homeplug(data, ethernet)

        if ethernet["ethertype"] == self.IPV6_ETHERTYPE:
            return self._validate_embedded_ipv6(data, ethernet)

        return None

    def _parse_embedded_ethernet(self, data: bytes, offset: int) -> dict[str, Any] | None:
        if offset < 0 or offset + 14 > len(data):
            return None

        destination_mac_bytes = data[offset:offset + 6]
        source_mac_bytes = data[offset + 6:offset + 12]
        if not self._valid_mac(destination_mac_bytes) or not self._valid_mac(source_mac_bytes):
            return None

        ethertype = int.from_bytes(data[offset + 12:offset + 14], "big")
        header_length = 14

        if ethertype in self.VLAN_ETHERTYPES:
            if offset + 18 > len(data):
                return None
            ethertype = int.from_bytes(data[offset + 16:offset + 18], "big")
            header_length = 18

        return {
            "offset": offset,
            "destination_mac": self._format_mac(destination_mac_bytes),
            "source_mac": self._format_mac(source_mac_bytes),
            "ethertype": ethertype,
            "header_length": header_length,
            "payload_offset": offset + header_length,
        }

    def _validate_embedded_homeplug(self, data: bytes, ethernet: dict[str, Any]) -> dict[str, Any] | None:
        payload_offset = ethernet["payload_offset"]
        if payload_offset + 3 > len(data):
            return None

        mmv = data[payload_offset]
        if mmv not in self.SUPPORTED_HOMEPLUG_MMV:
            return None

        mmtype = int.from_bytes(data[payload_offset + 1:payload_offset + 3], "little")
        minimum_message_length = self.SLAC_MINIMUM_LENGTHS.get(mmtype, 3)
        if len(data) - payload_offset < minimum_message_length:
            return None

        return {
            **ethernet,
            "protocol": "homeplug",
            "mmv": mmv,
            "mmtype": mmtype,
            "minimum_message_length": minimum_message_length,
        }

    def _validate_embedded_ipv6(self, data: bytes, ethernet: dict[str, Any]) -> dict[str, Any] | None:
        payload_offset = ethernet["payload_offset"]
        available = len(data) - payload_offset
        if available < 40:
            return None

        if data[payload_offset] >> 4 != 6:
            return None

        ipv6_payload_length = int.from_bytes(data[payload_offset + 4:payload_offset + 6], "big")
        ipv6_length = 40 + ipv6_payload_length
        if ipv6_length > available:
            return None

        source_bytes = data[payload_offset + 8:payload_offset + 24]
        destination_bytes = data[payload_offset + 24:payload_offset + 40]
        if source_bytes == b"\x00" * 16 or destination_bytes == b"\x00" * 16:
            return None

        return {
            **ethernet,
            "protocol": "ipv6",
            "frame_length": ethernet["header_length"] + ipv6_length,
            "ipv6_payload_length": ipv6_payload_length,
            "next_header": data[payload_offset + 6],
            "hop_limit": data[payload_offset + 7],
            "ipv6_source": str(IPv6Address(source_bytes)),
            "ipv6_destination": str(IPv6Address(destination_bytes)),
        }

    def _ipv6_subtype(self, next_header: int) -> str:
        names = {
            0: "HOPOPT",
            6: "TCP",
            17: "UDP",
            43: "ROUTING",
            44: "FRAGMENT",
            58: "ICMPV6",
            60: "DESTINATION_OPTIONS",
        }
        return names.get(next_header, f"NEXT_HEADER_{next_header}")

    def _next_boundary(self, data: bytes, start: int, metadata_offsets: list[int], status_offsets: list[int]) -> int:
        later_boundaries = [offset for offset in metadata_offsets + status_offsets if offset > start]
        if later_boundaries:
            return min(later_boundaries)
        return len(data)

    def _boundary_source(self, boundary: int, data_length: int, metadata_offsets: list[int], status_offsets: list[int]) -> str:
        if boundary in metadata_offsets:
            return "analyzer_metadata"
        if boundary in status_offsets:
            return "measurement_status"
        if boundary == data_length:
            return "payload_end"
        return "unknown"

    def _subrecord_offsets(self, data: bytes, signature: bytes) -> list[int]:
        offsets = []
        start = 0
        while True:
            signature_offset = data.find(signature, start)
            if signature_offset < 0:
                break
            record_offset = signature_offset - 1
            if record_offset >= 0:
                offsets.append(record_offset)
            start = signature_offset + 1
        return offsets

    def _extract_metadata(self, data: bytes, metadata_offsets: list[int]) -> dict[str, str]:
        candidates = [0] if data[16:19] == b"\x06\x00\x93" else []
        candidates.extend(metadata_offsets)
        for start in candidates:
            analyzer_id = self._length_prefixed_ascii(data, start + 33)
            build = self._length_prefixed_ascii(data, start + 46)
            product = self._length_prefixed_ascii(data, start + 73)
            if analyzer_id and build and product:
                return {"analyzer_id": analyzer_id, "build": build, "product": product}
        return {}

    def _length_prefixed_ascii(self, data: bytes, offset: int) -> str | None:
        if offset >= len(data):
            return None
        length = data[offset]
        end = offset + 1 + length
        if length == 0 or end > len(data):
            return None
        value = data[offset + 1:end]
        if not all(32 <= item <= 126 for item in value):
            return None
        return value.decode("ascii")

    def _embedded_identifier(self, data: bytes) -> str | None:
        if len(data) < 35:
            return None
        if data[24:29] not in (
            b"\x00\x00\x01\x01\x00",
            b"\x00\x00\x01\x00\x00",
            b"\x00\x00\x02\x01\x00",
        ):
            return None
        return self._format_mac(data[29:35])

    def _recover_regions(self, data: bytes, metadata_offsets: list[int], status_offsets: list[int]) -> list[dict[str, Any]]:
        boundaries = {0, len(data)}
        boundaries.update(metadata_offsets)
        boundaries.update(status_offsets)
        ordered = sorted(boundaries)
        regions = []
        for index in range(len(ordered) - 1):
            start = ordered[index]
            end = ordered[index + 1]
            if start in metadata_offsets:
                region_type = "analyzer_metadata"
            elif start in status_offsets:
                region_type = "measurement_status"
            elif start == 0:
                region_type = "primary_record"
            else:
                region_type = "unclassified"
            regions.append({
                "type": region_type,
                "offset": start,
                "length": end - start,
                "sha256": self._sha256(data[start:end]),
            })
        return regions

    def _valid_mac(self, value: bytes) -> bool:
        return len(value) == 6 and value != b"\x00" * 6

    def _format_mac(self, value: bytes) -> str:
        return ":".join(f"{item:02x}" for item in value)

    def _sha256(self, data: bytes) -> str:
        return sha256(data).hexdigest()

    def _source_file(self, event: TraceEvent) -> str | None:
        value = event.payload.get("source_file")
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, str):
            return value
        return None
