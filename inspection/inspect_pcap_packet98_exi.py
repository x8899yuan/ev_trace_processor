from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path
from typing import Iterator

from services.v2g_exi_decoder_service import V2GExiDecoderService

DEFAULT_PCAP = Path(r"data\pcap\20250401122302-700006-18-G3-PWR-LOSS-OLD-SOFT-msduEx.pcap")
PACKET_NUMBER = 98


def iter_packet_data(path: Path) -> Iterator[tuple[int, bytes]]:
    with path.open("rb") as stream:
        global_header = stream.read(24)
        formats = {
            b"\xd4\xc3\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">",
            b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\x3c\x4d": ">",
        }
        if len(global_header) != 24 or global_header[:4] not in formats:
            raise ValueError("Unsupported classic-PCAP header")
        endian = formats[global_header[:4]]
        linktype = struct.unpack(endian + "I", global_header[20:24])[0]
        if linktype != 160:
            raise ValueError(f"Expected DLT 160 capture, found link type {linktype}")
        number = 0
        while True:
            header = stream.read(16)
            if not header:
                return
            if len(header) != 16:
                raise ValueError("Incomplete PCAP packet header")
            _, _, captured_length, _ = struct.unpack(endian + "IIII", header)
            data = stream.read(captured_length)
            if len(data) != captured_length:
                raise ValueError("Incomplete PCAP packet data")
            number += 1
            yield number, data


def ipv6_candidates(data: bytes) -> Iterator[int]:
    for offset in range(max(0, len(data) - 39)):
        if data[offset] >> 4 != 6:
            continue
        payload_length = struct.unpack("!H", data[offset + 4:offset + 6])[0]
        if offset + 40 + payload_length <= len(data):
            yield offset


def format_ipv6(raw: bytes) -> str:
    return ":".join(f"{word:x}" for word in struct.unpack("!8H", raw))


def parse_tcp(ipv6: bytes):
    payload_length = struct.unpack("!H", ipv6[4:6])[0]
    next_header = ipv6[6]
    cursor = 40
    end = min(len(ipv6), 40 + payload_length)
    for _ in range(8):
        if next_header == 6:
            break
        if next_header in (0, 43, 60):
            if cursor + 2 > end:
                return None
            next_header, length = ipv6[cursor], ipv6[cursor + 1]
            cursor += (length + 1) * 8
        elif next_header == 44:
            if cursor + 8 > end:
                return None
            next_header = ipv6[cursor]
            cursor += 8
        elif next_header == 51:
            if cursor + 2 > end:
                return None
            next_header, length = ipv6[cursor], ipv6[cursor + 1]
            cursor += (length + 2) * 4
        else:
            return None
    if next_header != 6 or cursor + 20 > end:
        return None
    tcp = ipv6[cursor:end]
    source_port, destination_port = struct.unpack("!HH", tcp[:4])
    header_length = (tcp[12] >> 4) * 4
    if header_length < 20 or header_length > len(tcp):
        return None
    return (
        format_ipv6(ipv6[8:24]),
        format_ipv6(ipv6[24:40]),
        source_port,
        destination_port,
        tcp[header_length:],
    )


def extract_packet98(path: Path):
    for number, data in iter_packet_data(path):
        if number != PACKET_NUMBER:
            continue
        for offset in ipv6_candidates(data):
            parsed = parse_tcp(data[offset:])
            if not parsed:
                continue
            source, destination, source_port, destination_port, tcp = parsed
            cursor = 0
            while cursor + 8 <= len(tcp):
                if tcp[cursor:cursor + 2] != b"\x01\xfe":
                    cursor += 1
                    continue
                payload_type = struct.unpack("!H", tcp[cursor + 2:cursor + 4])[0]
                payload_length = struct.unpack("!I", tcp[cursor + 4:cursor + 8])[0]
                end = cursor + 8 + payload_length
                if end > len(tcp):
                    break
                if payload_type == 0x8001:
                    return offset, source, destination, source_port, destination_port, tcp[cursor + 8:end]
                cursor = end
        raise RuntimeError("No complete V2GTP 0x8001 payload recovered from packet 98")
    raise RuntimeError("Packet 98 not found")


def bit_rows(data: bytes):
    rows = []
    for index, value in enumerate(data):
        rows.append((index, f"0x{value:02X}", f"{value:08b}"))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect packet 98 EXI bytes after V2G application-protocol negotiation.")
    parser.add_argument("pcap", nargs="?", type=Path, default=DEFAULT_PCAP)
    args = parser.parse_args()
    if not args.pcap.is_file():
        print(f"PCAP file not found: {args.pcap}")
        return 2
    try:
        offset, source, destination, source_port, destination_port, payload = extract_packet98(args.pcap)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Inspection failed: {exc}")
        return 1

    result = V2GExiDecoderService().inspect(payload)
    print("=" * 80)
    print("Packet 98 pure-Python EXI inspection")
    print("=" * 80)
    print(f"PCAP file          : {args.pcap}")
    print(f"PCAP packet        : {PACKET_NUMBER}")
    print(f"Embedded IPv6 off. : {offset}")
    print(f"TCP direction      : {source}:{source_port} -> {destination}:{destination_port}")
    print(f"EXI byte length    : {len(payload)}")
    print(f"SHA-256            : {hashlib.sha256(payload).hexdigest()}")
    print(f"EXI full hex       : {payload.hex(' ').upper()}")
    print(f"Current kind       : {result.kind}")
    print(f"Current status     : {result.status}")
    print(f"Current confidence : {result.confidence}")
    print(f"Selected schema    : {result.selected_schema_id}")
    print("=" * 80)
    print("Byte / bit view")
    print("=" * 80)
    for index, hex_value, bits in bit_rows(payload):
        marker = " EXI header" if index == 0 and payload[0] == 0x80 else ""
        print(f"byte {index:02d}: {hex_value}  {bits}{marker}")
    print("=" * 80)
    print("Post-negotiation context")
    print("=" * 80)
    print("Packet 93: SupportedAppProtocolReq candidate")
    print("Packet 95: SupportedAppProtocolRes, successful negotiation, schema ID 0")
    print("Packet 98: first observed post-negotiation V2GTP 0x8001 payload")
    print("No application-message name is asserted until its schema grammar is proven.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
