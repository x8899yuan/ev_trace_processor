import argparse
from collections import Counter, defaultdict
from pathlib import Path

import dpkt


DEFAULT_PCAP = Path(
    r"data\pcap\20250401122302-700006-18-G3-PWR-LOSS-OLD-SOFT-mpdu.pcap"
)
KNOWN_ETHERTYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x8100: "VLAN",
    0x86DD: "IPv6",
    0x88A8: "QinQ",
    0x88E1: "HomePlug",
}
VLAN_TYPES = {0x8100, 0x88A8}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", nargs="?", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--preview", type=int, default=32)
    parser.add_argument("--show-candidates", action="store_true")
    return parser.parse_args()


def open_pcap(path):
    handle = path.open("rb")
    try:
        reader = dpkt.pcap.Reader(handle)
        return handle, reader, "pcap"
    except (ValueError, dpkt.dpkt.NeedData):
        handle.seek(0)
    try:
        reader = dpkt.pcapng.Reader(handle)
        return handle, reader, "pcapng"
    except Exception:
        handle.close()
        raise


def format_mac(value):
    return ":".join(f"{item:02x}" for item in value)


def valid_mac(value):
    return len(value) == 6 and value != b"\x00" * 6


def validate_ipv4(data, offset):
    if offset + 20 > len(data):
        return False
    first = data[offset]
    if first >> 4 != 4:
        return False
    ihl = (first & 0x0F) * 4
    if ihl < 20 or offset + ihl > len(data):
        return False
    total_length = int.from_bytes(data[offset + 2:offset + 4], "big")
    return ihl <= total_length <= len(data) - offset


def validate_arp(data, offset):
    if offset + 28 > len(data):
        return False
    return (
        int.from_bytes(data[offset:offset + 2], "big") == 1
        and int.from_bytes(data[offset + 2:offset + 4], "big") == 0x0800
        and data[offset + 4] == 6
        and data[offset + 5] == 4
        and int.from_bytes(data[offset + 6:offset + 8], "big") in {1, 2}
    )


def validate_ipv6(data, offset):
    if offset + 40 > len(data):
        return False
    if data[offset] >> 4 != 6:
        return False
    payload_length = int.from_bytes(data[offset + 4:offset + 6], "big")
    return 40 + payload_length <= len(data) - offset


def validate_homeplug(data, offset):
    if offset + 3 > len(data):
        return False
    return data[offset] in {0x00, 0x01}


def parse_candidate(data, offset):
    if offset + 14 > len(data):
        return None
    destination = data[offset:offset + 6]
    source = data[offset + 6:offset + 12]
    if not valid_mac(destination) or not valid_mac(source):
        return None

    outer_type = int.from_bytes(data[offset + 12:offset + 14], "big")
    ethertype = outer_type
    header_length = 14
    if outer_type in VLAN_TYPES:
        if offset + 18 > len(data):
            return None
        ethertype = int.from_bytes(data[offset + 16:offset + 18], "big")
        header_length = 18

    payload_offset = offset + header_length
    if ethertype == 0x0800:
        valid = validate_ipv4(data, payload_offset)
    elif ethertype == 0x0806:
        valid = validate_arp(data, payload_offset)
    elif ethertype == 0x86DD:
        valid = validate_ipv6(data, payload_offset)
    elif ethertype == 0x88E1:
        valid = validate_homeplug(data, payload_offset)
    else:
        return None

    if not valid:
        return None

    result = {
        "offset": offset,
        "source_mac": format_mac(source),
        "destination_mac": format_mac(destination),
        "outer_ethertype": outer_type,
        "ethertype": ethertype,
        "protocol": KNOWN_ETHERTYPES.get(ethertype, f"0x{ethertype:04X}"),
        "payload_offset": payload_offset,
    }

    if ethertype == 0x88E1 and payload_offset + 3 <= len(data):
        result["mmv"] = data[payload_offset]
        result["mmtype"] = int.from_bytes(
            data[payload_offset + 1:payload_offset + 3], "little"
        )
    elif ethertype == 0x86DD:
        result["next_header"] = data[payload_offset + 6]
        result["ipv6_payload_length"] = int.from_bytes(
            data[payload_offset + 4:payload_offset + 6], "big"
        )

    return result


def main():
    args = parse_args()
    if not args.pcap.exists():
        raise SystemExit(f"PCAP file not found: {args.pcap}")
    if args.limit < 0 or args.preview < 0:
        raise SystemExit("--limit and --preview cannot be negative")

    handle, reader, container_type = open_pcap(args.pcap)
    packet_count = 0
    length_counts = Counter()
    first_bytes = Counter()
    candidate_counts = Counter()
    offset_counts = defaultdict(Counter)
    mmtype_counts = Counter()
    ipv6_next_headers = Counter()
    candidates = []

    try:
        datalink = reader.datalink() if hasattr(reader, "datalink") else None
        for packet_number, (timestamp, packet) in enumerate(reader, start=1):
            packet_count += 1
            data = bytes(packet)
            length_counts[len(data)] += 1
            first_bytes[data[:8].hex(" ")] += 1

            for offset in range(max(0, len(data) - 13)):
                candidate = parse_candidate(data, offset)
                if candidate is None:
                    continue
                protocol = candidate["protocol"]
                candidate_counts[protocol] += 1
                offset_counts[protocol][offset] += 1
                if "mmtype" in candidate:
                    mmtype_counts[f"0x{candidate['mmtype']:04X}"] += 1
                if "next_header" in candidate:
                    ipv6_next_headers[candidate["next_header"]] += 1
                if len(candidates) < args.limit:
                    candidates.append(
                        {
                            **candidate,
                            "packet_number": packet_number,
                            "timestamp": timestamp,
                            "preview": data[offset:offset + args.preview].hex(" "),
                        }
                    )
    finally:
        handle.close()

    if args.show_candidates:
        for item in candidates:
            print()
            print(
                f"packet={item['packet_number']} timestamp={item['timestamp']:.6f} "
                f"offset={item['offset']} protocol={item['protocol']}"
            )
            print(
                f"  {item['source_mac']} -> {item['destination_mac']} "
                f"ethertype=0x{item['ethertype']:04X}"
            )
            if "mmtype" in item:
                print(
                    f"  mmv=0x{item['mmv']:02X} "
                    f"mmtype=0x{item['mmtype']:04X}"
                )
            if "next_header" in item:
                print(
                    f"  ipv6_payload_length={item['ipv6_payload_length']} "
                    f"next_header={item['next_header']}"
                )
            print(f"  preview={item['preview']}")

    print()
    print("=" * 72)
    print("MPDU PCAP structure inspection summary")
    print("=" * 72)
    print(f"PCAP                 : {args.pcap}")
    print(f"Container            : {container_type}")
    print(f"DLT/link type        : {datalink}")
    print(f"Packets              : {packet_count}")

    print()
    print("Most common packet lengths:")
    for length, count in length_counts.most_common(12):
        print(f"  {length:<8} {count}")

    print()
    print("Most common first 8 bytes:")
    for value, count in first_bytes.most_common(12):
        print(f"  {value:<24} {count}")

    print()
    print("Structurally validated embedded protocols:")
    if candidate_counts:
        for protocol, count in candidate_counts.most_common():
            print(f"  {protocol:<12} {count}")
    else:
        print("  none")

    print()
    print("Recurring validated offsets by protocol:")
    if offset_counts:
        for protocol, counts in sorted(offset_counts.items()):
            common = ", ".join(
                f"{offset}:{count}" for offset, count in counts.most_common(10)
            )
            print(f"  {protocol:<12} {common}")
    else:
        print("  none")

    print()
    print("HomePlug MMTYPEs:")
    if mmtype_counts:
        for mmtype, count in mmtype_counts.most_common(20):
            print(f"  {mmtype:<12} {count}")
    else:
        print("  none")

    print()
    print("IPv6 next headers:")
    if ipv6_next_headers:
        for value, count in ipv6_next_headers.most_common():
            print(f"  {value:<8} {count}")
    else:
        print("  none")


if __name__ == "__main__":
    main()
