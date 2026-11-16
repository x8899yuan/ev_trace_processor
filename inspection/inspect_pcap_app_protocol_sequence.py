from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from services.v2g_exi_decoder_service import V2GExiDecoderService

DEFAULT_PCAP = Path(r"data\pcap\20250401122302-700006-18-G3-PWR-LOSS-OLD-SOFT-msduEx.pcap")


@dataclass(frozen=True)
class Packet:
    number: int
    data: bytes


@dataclass(frozen=True)
class V2GMessage:
    packet: int
    ipv6_offset: int
    src: str
    dst: str
    sport: int
    dport: int
    payload_type: int
    payload: bytes


def iter_packets(path: Path) -> Iterator[Packet]:
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
            yield Packet(number, data)


def format_ipv6(raw: bytes) -> str:
    return ":".join(f"{value:x}" for value in struct.unpack("!8H", raw))


def ipv6_candidates(data: bytes) -> Iterator[int]:
    for offset in range(max(0, len(data) - 39)):
        if data[offset] >> 4 != 6:
            continue
        payload_length = struct.unpack("!H", data[offset + 4:offset + 6])[0]
        if offset + 40 + payload_length <= len(data):
            yield offset


def parse_tcp(ipv6: bytes):
    if len(ipv6) < 40 or ipv6[0] >> 4 != 6:
        return None
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
    sport, dport = struct.unpack("!HH", tcp[:4])
    header_length = (tcp[12] >> 4) * 4
    if header_length < 20 or header_length > len(tcp):
        return None
    return format_ipv6(ipv6[8:24]), format_ipv6(ipv6[24:40]), sport, dport, tcp[header_length:]


def iter_v2g_messages(packet: Packet) -> Iterator[V2GMessage]:
    for offset in ipv6_candidates(packet.data):
        parsed = parse_tcp(packet.data[offset:])
        if not parsed:
            continue
        src, dst, sport, dport, tcp = parsed
        cursor = 0
        found = False
        while cursor + 8 <= len(tcp):
            if tcp[cursor:cursor + 2] != b"\x01\xfe":
                cursor += 1
                continue
            payload_type = struct.unpack("!H", tcp[cursor + 2:cursor + 4])[0]
            payload_length = struct.unpack("!I", tcp[cursor + 4:cursor + 8])[0]
            end = cursor + 8 + payload_length
            if end > len(tcp):
                break
            found = True
            yield V2GMessage(packet.number, offset, src, dst, sport, dport, payload_type, tcp[cursor + 8:end])
            cursor = end
        if found:
            return


def direction_label(message: V2GMessage, request: Optional[V2GMessage]) -> str:
    if request is None:
        return "initial"
    if message.src == request.src and message.sport == request.sport:
        return "same-as-request"
    if message.src == request.dst and message.dst == request.src:
        return "reverse-of-request"
    return "other"


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect the first V2G application-protocol request/response sequence in a DLT 160 PCAP.")
    parser.add_argument("pcap", nargs="?", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--start-packet", type=int, default=93)
    parser.add_argument("--count", type=int, default=8)
    args = parser.parse_args()
    if not args.pcap.is_file():
        print(f"PCAP file not found: {args.pcap}")
        return 2
    if args.count < 1:
        print("--count must be at least 1")
        return 2

    decoder = V2GExiDecoderService()
    selected = []
    try:
        for packet in iter_packets(args.pcap):
            if packet.number < args.start_packet:
                continue
            for message in iter_v2g_messages(packet):
                if message.payload_type == 0x8001:
                    selected.append(message)
                    if len(selected) >= args.count:
                        break
            if len(selected) >= args.count:
                break
    except (OSError, ValueError) as exc:
        print(f"Inspection failed: {exc}")
        return 1

    if not selected:
        print(f"No V2GTP 0x8001 messages found from packet {args.start_packet}")
        return 1

    request = selected[0]
    print("=" * 88)
    print("Pure-Python V2G application-protocol sequence inspection")
    print("=" * 88)
    print(f"PCAP file       : {args.pcap}")
    print(f"Starting packet : {args.start_packet}")
    print(f"Messages shown  : {len(selected)}")
    print("=" * 88)

    for index, message in enumerate(selected, 1):
        result = decoder.inspect(message.payload)
        namespaces = ", ".join(protocol.namespace for protocol in result.protocols) or "none"
        selected_schema = str(result.selected_schema_id) if result.selected_schema_id is not None else "not decoded"
        print(f"[{index}] Packet            : {message.packet}")
        print(f"    Direction         : {message.src}:{message.sport} -> {message.dst}:{message.dport}")
        print(f"    Relative direction: {direction_label(message, request)}")
        print(f"    Embedded IPv6 off.: {message.ipv6_offset}")
        print(f"    V2GTP payload type: 0x{message.payload_type:04X}")
        print(f"    EXI length        : {len(message.payload)}")
        print(f"    SHA-256           : {hashlib.sha256(message.payload).hexdigest()}")
        print(f"    Decoder kind      : {result.kind}")
        print(f"    Decoder status    : {result.status}")
        print(f"    Confidence        : {result.confidence}")
        print(f"    Advertised NS     : {namespaces}")
        print(f"    Selected schema   : {selected_schema}")
        print(f"    EXI full hex      : {message.payload.hex(' ').upper()}")
        print("-" * 88)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
