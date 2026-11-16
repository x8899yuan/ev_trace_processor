from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

DEFAULT_PCAP = Path(r"data\pcap\20250401122302-700006-18-G3-PWR-LOSS-OLD-SOFT-msduEx.pcap")
PACKET_NUMBER = 93
KNOWN_NAMESPACES = (
    "urn:iso:15118:2:2010:AppProtocol",
    "urn:iso:15118:2:2013:MsgDef",
    "urn:din:70121:2012:MsgDef",
    "urn:iso:std:iso:15118:-20:CommonMessages",
)


@dataclass(frozen=True)
class Candidate:
    namespace: str
    start_bit: int
    end_bit: int
    byte_aligned: bool


def iter_packets(path: Path) -> Iterator[tuple[int, bytes]]:
    with path.open("rb") as stream:
        gh = stream.read(24)
        formats = {
            b"\xd4\xc3\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">",
            b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\x3c\x4d": ">",
        }
        if len(gh) != 24 or gh[:4] not in formats:
            raise ValueError("Unsupported classic-PCAP header")
        endian = formats[gh[:4]]
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        if linktype != 160:
            raise ValueError(f"Expected DLT 160 capture, found link type {linktype}")
        number = 0
        while True:
            ph = stream.read(16)
            if not ph:
                return
            if len(ph) != 16:
                raise ValueError("Incomplete PCAP packet header")
            _, _, captured, _ = struct.unpack(endian + "IIII", ph)
            data = stream.read(captured)
            if len(data) != captured:
                raise ValueError("Incomplete PCAP packet data")
            number += 1
            yield number, data


def ipv6_candidates(data: bytes) -> Iterator[int]:
    for offset in range(max(0, len(data) - 39)):
        if data[offset] >> 4 != 6:
            continue
        plen = struct.unpack("!H", data[offset + 4:offset + 6])[0]
        if offset + 40 + plen <= len(data):
            yield offset


def tcp_payload(ipv6: bytes):
    plen = struct.unpack("!H", ipv6[4:6])[0]
    nh = ipv6[6]
    cursor = 40
    end = min(len(ipv6), 40 + plen)
    for _ in range(8):
        if nh == 6:
            break
        if nh in (0, 43, 60):
            if cursor + 2 > end:
                return None
            nh, length = ipv6[cursor], ipv6[cursor + 1]
            cursor += (length + 1) * 8
        elif nh == 44:
            if cursor + 8 > end:
                return None
            nh = ipv6[cursor]
            cursor += 8
        elif nh == 51:
            if cursor + 2 > end:
                return None
            nh, length = ipv6[cursor], ipv6[cursor + 1]
            cursor += (length + 2) * 4
        else:
            return None
    if nh != 6 or cursor + 20 > end:
        return None
    tcp = ipv6[cursor:end]
    hlen = (tcp[12] >> 4) * 4
    if hlen < 20 or hlen > len(tcp):
        return None
    return tcp[hlen:]


def extract_exi(path: Path) -> bytes:
    for number, data in iter_packets(path):
        if number != PACKET_NUMBER:
            continue
        for offset in ipv6_candidates(data):
            tcp = tcp_payload(data[offset:])
            if not tcp:
                continue
            cursor = 0
            while cursor + 8 <= len(tcp):
                if tcp[cursor:cursor + 2] != b"\x01\xfe":
                    cursor += 1
                    continue
                ptype = struct.unpack("!H", tcp[cursor + 2:cursor + 4])[0]
                size = struct.unpack("!I", tcp[cursor + 4:cursor + 8])[0]
                end = cursor + 8 + size
                if end > len(tcp):
                    break
                if ptype == 0x8001:
                    return tcp[cursor + 8:end]
                cursor = end
        raise RuntimeError("No V2GTP 0x8001 payload recovered from packet 93")
    raise RuntimeError("Packet 93 not found")


def bits(data: bytes) -> str:
    return "".join(f"{value:08b}" for value in data)


def find_namespace_candidates(payload: bytes) -> list[Candidate]:
    stream = bits(payload)
    candidates = []
    for namespace in KNOWN_NAMESPACES:
        target = bits(namespace.encode("ascii"))
        start = 0
        while True:
            index = stream.find(target, start)
            if index < 0:
                break
            candidates.append(Candidate(namespace, index, index + len(target), index % 8 == 0))
            start = index + 1
    return sorted(candidates, key=lambda item: item.start_bit)


def nearby_bits(payload: bytes, candidate: Candidate, before: int = 32, after: int = 48) -> str:
    stream = bits(payload)
    left = max(0, candidate.start_bit - before)
    right = min(len(stream), candidate.end_bit + after)
    return stream[left:right]


def nearby_hex(payload: bytes, candidate: Candidate, radius: int = 8) -> str:
    first = max(0, candidate.start_bit // 8 - radius)
    last = min(len(payload), (candidate.end_bit + 7) // 8 + radius)
    return payload[first:last].hex(" ").upper()


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect packet 93 SupportedAppProtocol fields conservatively using pure Python.")
    parser.add_argument("pcap", nargs="?", type=Path, default=DEFAULT_PCAP)
    args = parser.parse_args()
    if not args.pcap.is_file():
        print(f"PCAP file not found: {args.pcap}")
        return 2
    try:
        payload = extract_exi(args.pcap)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Inspection failed: {exc}")
        return 1

    candidates = find_namespace_candidates(payload)
    print("=" * 88)
    print("Packet 93 SupportedAppProtocol field inspection")
    print("=" * 88)
    print(f"PCAP file       : {args.pcap}")
    print(f"Packet          : {PACKET_NUMBER}")
    print(f"EXI length      : {len(payload)}")
    print(f"SHA-256         : {hashlib.sha256(payload).hexdigest()}")
    print(f"EXI full hex    : {payload.hex(' ').upper()}")
    print(f"Namespace hits  : {len(candidates)}")
    print("=" * 88)

    if not candidates:
        print("No known namespace bit patterns were recovered.")
    for index, candidate in enumerate(candidates, 1):
        print(f"[{index}] Namespace       : {candidate.namespace}")
        print(f"    Start bit       : {candidate.start_bit}")
        print(f"    End bit         : {candidate.end_bit}")
        print(f"    Byte aligned    : {candidate.byte_aligned}")
        print(f"    Nearby hex      : {nearby_hex(payload, candidate)}")
        print(f"    Nearby bits     : {nearby_bits(payload, candidate)}")
        print("-" * 88)

    print("Field-decoding status")
    print("=" * 88)
    print("Namespace       : evidence recovered where shown above")
    print("MajorVersion    : not decoded")
    print("MinorVersion    : not decoded")
    print("SchemaID        : not decoded")
    print("Priority        : not decoded")
    print("Packet 95 says  : selected schema ID 0")
    print("This utility does not assign schema ID 0 to a namespace until the packet-93 field grammar is proven.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
