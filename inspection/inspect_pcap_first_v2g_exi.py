from __future__ import annotations
import argparse, hashlib, struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

DEFAULT_PCAP = Path(r"data\pcap\20250401122302-700006-18-G3-PWR-LOSS-OLD-SOFT-msduEx.pcap")

@dataclass(frozen=True)
class Packet:
    number: int
    ts: float
    data: bytes

@dataclass(frozen=True)
class Message:
    packet: int
    src: str
    dst: str
    sport: int
    dport: int
    payload_type: int
    payload: bytes
    ipv6_offset: int


def packets(path: Path) -> Iterator[Packet]:
    with path.open("rb") as f:
        gh = f.read(24)
        if len(gh) != 24:
            raise ValueError("Incomplete PCAP header")
        versions = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6), b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
        if gh[:4] not in versions:
            raise ValueError("Not classic PCAP")
        endian, scale = versions[gh[:4]]
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        if linktype not in (1, 160):
            raise ValueError(f"Unsupported PCAP link type {linktype}")
        n = 0
        while True:
            ph = f.read(16)
            if not ph:
                return
            if len(ph) != 16:
                raise ValueError("Incomplete packet header")
            sec, frac, size, _ = struct.unpack(endian + "IIII", ph)
            data = f.read(size)
            if len(data) != size:
                raise ValueError("Incomplete packet")
            n += 1
            yield Packet(n, sec + frac / scale, data)


def ip6(raw: bytes) -> str:
    return ":".join(f"{x:x}" for x in struct.unpack("!8H", raw))


def ipv6_candidates(data: bytes) -> Iterator[int]:
    for off in range(max(0, len(data) - 39)):
        if data[off] >> 4 != 6 or off + 40 > len(data):
            continue
        plen = struct.unpack("!H", data[off + 4:off + 6])[0]
        if off + 40 + plen <= len(data):
            yield off


def parse_tcp(data: bytes, off: int):
    x = data[off:]
    if len(x) < 40 or x[0] >> 4 != 6:
        return None
    plen = struct.unpack("!H", x[4:6])[0]
    nh, pos, end = x[6], 40, min(len(x), 40 + plen)
    for _ in range(8):
        if nh == 6:
            break
        if nh in (0, 43, 60):
            if pos + 2 > end: return None
            nh, l = x[pos], x[pos + 1]; pos += (l + 1) * 8
        elif nh == 44:
            if pos + 8 > end: return None
            nh = x[pos]; pos += 8
        elif nh == 51:
            if pos + 2 > end: return None
            nh, l = x[pos], x[pos + 1]; pos += (l + 2) * 4
        else:
            return None
    if nh != 6 or pos + 20 > end:
        return None
    tcp = x[pos:end]
    sport, dport = struct.unpack("!HH", tcp[:4])
    hlen = (tcp[12] >> 4) * 4
    if hlen < 20 or hlen > len(tcp):
        return None
    return ip6(x[8:24]), ip6(x[24:40]), sport, dport, tcp[hlen:]


def messages(pkt: Packet) -> Iterator[Message]:
    for off in ipv6_candidates(pkt.data):
        parsed = parse_tcp(pkt.data, off)
        if not parsed:
            continue
        src, dst, sport, dport, data = parsed
        pos = 0
        while pos + 8 <= len(data):
            if data[pos:pos + 2] != b"\x01\xfe":
                pos += 1
                continue
            ptype = struct.unpack("!H", data[pos + 2:pos + 4])[0]
            size = struct.unpack("!I", data[pos + 4:pos + 8])[0]
            end = pos + 8 + size
            if end > len(data):
                break
            yield Message(pkt.number, src, dst, sport, dport, ptype, data[pos + 8:end], off)
            pos = end
        return


def exi_preamble(data: bytes):
    if not data:
        return None
    off = 4 if data.startswith(b"$EXI") else 0
    if off >= len(data):
        return None
    b = data[off]
    return {"cookie": bool(off), "distinguishing_bits": f"{b >> 6:02b}", "options_present": bool((b >> 5) & 1), "version_nibble": (b >> 1) & 0xF}


def find(path: Path, packet: Optional[int]) -> Message:
    first = None
    for pkt in packets(path):
        for msg in messages(pkt):
            if msg.payload_type != 0x8001:
                continue
            if first is None: first = msg
            if packet is not None and pkt.number == packet: return msg
    if packet is not None:
        raise RuntimeError(f"No complete V2GTP 0x8001 message recovered from packet {packet}")
    if first: return first
    raise RuntimeError("No complete V2GTP 0x8001 message recovered")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", nargs="?", type=Path, default=DEFAULT_PCAP)
    ap.add_argument("--packet", type=int, default=93)
    a = ap.parse_args()
    if not a.pcap.is_file():
        print(f"PCAP file not found: {a.pcap}"); return 2
    try:
        m = find(a.pcap, a.packet)
    except Exception as e:
        print(f"Inspection failed: {e}"); return 1
    h = exi_preamble(m.payload)
    print("=" * 72)
    print("Pure-Python DLT 160 V2G EXI inspection")
    print("=" * 72)
    print(f"PCAP file          : {a.pcap}")
    print(f"PCAP packet        : {m.packet}")
    print(f"Embedded IPv6 off. : {m.ipv6_offset}")
    print(f"TCP direction      : {m.src}:{m.sport} -> {m.dst}:{m.dport}")
    print(f"V2GTP payload type : 0x{m.payload_type:04X}")
    print(f"EXI byte length    : {len(m.payload)}")
    print(f"SHA-256            : {hashlib.sha256(m.payload).hexdigest()}")
    print(f"EXI preamble       : {h}")
    print(f"EXI full hex       : {m.payload.hex(' ').upper()}")
    print("=" * 72)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
