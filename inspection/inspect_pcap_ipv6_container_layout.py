import argparse
from collections import Counter
from ipaddress import IPv6Address
from pathlib import Path

from readers.pcap_reader import PcapReader
from services.iotecha_hpgp_decoder_service import IotechaHpgpDecoderService


DEFAULT_PCAP = Path(r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap")
IPV6_ETHERTYPE = 0x86DD
VLAN_ETHERTYPES = {0x8100, 0x88A8}
SLAC_MATCH_CNF = "CM_SLAC_MATCH.CNF"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", nargs="?", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--start-packet", type=int)
    parser.add_argument("--end-packet", type=int)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--preview", type=int, default=48)
    parser.add_argument("--show-rejected", action="store_true")
    return parser.parse_args()


def valid_mac(value):
    return len(value) == 6 and value != b"\x00" * 6


def format_mac(value):
    return ":".join(f"{item:02x}" for item in value)


def find_last_slac_match_cnf(records):
    matches = []
    for record in records:
        packet_index = record.get("packet_index")
        if not isinstance(packet_index, int):
            continue
        for frame in record.get("embedded_frames", []):
            if frame.get("subtype") == SLAC_MATCH_CNF:
                matches.append(packet_index + 1)
    return max(matches) if matches else None


def candidate_offsets(data):
    maximum = len(data) - 14
    if maximum < 0:
        return
    for offset in range(maximum + 1):
        if data[offset + 12:offset + 14] == b"\x86\xdd":
            yield offset
            continue
        outer_type = int.from_bytes(data[offset + 12:offset + 14], "big")
        if outer_type in VLAN_ETHERTYPES and offset + 18 <= len(data):
            if data[offset + 16:offset + 18] == b"\x86\xdd":
                yield offset


def validate_candidate(data, offset):
    if offset + 14 > len(data):
        return None, "ethernet_too_short"

    destination_mac = data[offset:offset + 6]
    source_mac = data[offset + 6:offset + 12]

    if not valid_mac(destination_mac) or not valid_mac(source_mac):
        return None, "invalid_mac"

    ethertype = int.from_bytes(data[offset + 12:offset + 14], "big")
    header_length = 14

    if ethertype in VLAN_ETHERTYPES:
        if offset + 18 > len(data):
            return None, "vlan_too_short"
        ethertype = int.from_bytes(data[offset + 16:offset + 18], "big")
        header_length = 18

    if ethertype != IPV6_ETHERTYPE:
        return None, "not_ipv6"

    ipv6_offset = offset + header_length
    available = len(data) - ipv6_offset

    if available < 40:
        return None, "ipv6_too_short"

    if data[ipv6_offset] >> 4 != 6:
        return None, "ipv6_invalid_version"

    payload_length = int.from_bytes(data[ipv6_offset + 4:ipv6_offset + 6], "big")
    ipv6_length = 40 + payload_length

    if ipv6_length > available:
        return None, "ipv6_payload_exceeds_available"

    source = data[ipv6_offset + 8:ipv6_offset + 24]
    destination = data[ipv6_offset + 24:ipv6_offset + 40]

    if source == b"\x00" * 16:
        return None, "ipv6_zero_source"

    if destination == b"\x00" * 16:
        return None, "ipv6_zero_destination"

    frame_length = header_length + ipv6_length

    return {
        "offset": offset,
        "frame_length": frame_length,
        "source_mac": format_mac(source_mac),
        "destination_mac": format_mac(destination_mac),
        "ipv6_source": str(IPv6Address(source)),
        "ipv6_destination": str(IPv6Address(destination)),
        "payload_length": payload_length,
        "next_header": data[ipv6_offset + 6],
        "hop_limit": data[ipv6_offset + 7],
        "preview": data[offset:offset + min(frame_length, 48)],
    }, "valid"


def next_header_name(value):
    return {
        0: "HOPOPT",
        6: "TCP",
        17: "UDP",
        43: "ROUTING",
        44: "FRAGMENT",
        58: "ICMPV6",
        60: "DESTINATION_OPTIONS",
    }.get(value, f"NEXT_HEADER_{value}")


def main():
    args = parse_args()

    if not args.pcap.exists():
        raise SystemExit(f"PCAP file not found: {args.pcap}")
    if args.limit < 0:
        raise SystemExit("--limit cannot be negative")
    if args.preview < 0:
        raise SystemExit("--preview cannot be negative")

    trace = PcapReader().read(args.pcap)
    service = IotechaHpgpDecoderService()
    records = service.decode_trace(trace)

    match_packet = find_last_slac_match_cnf(records)
    start_packet = args.start_packet
    if start_packet is None:
        start_packet = match_packet + 1 if match_packet is not None else 1

    end_packet = args.end_packet
    rejection_counts = Counter()
    raw_matches = 0
    scanned_records = 0
    findings = []

    for record in records:
        packet_index = record.get("packet_index")
        packet_number = packet_index + 1 if isinstance(packet_index, int) else None
        if packet_number is None or packet_number < start_packet:
            continue
        if end_packet is not None and packet_number > end_packet:
            continue

        data = None
        event = trace.events[packet_index] if 0 <= packet_index < len(trace.events) else None
        if event is not None:
            value = event.payload.get("ethernet_payload")
            if isinstance(value, bytes):
                data = value

        if data is None:
            continue

        scanned_records += 1

        for offset in candidate_offsets(data):
            raw_matches += 1
            candidate, reason = validate_candidate(data, offset)
            if candidate is None:
                rejection_counts[reason] += 1
                if args.show_rejected:
                    print(f"REJECT packet={packet_number} offset={offset} reason={reason}")
                continue

            candidate["packet_number"] = packet_number
            candidate["timestamp"] = record.get("timestamp")
            candidate["record_class"] = record.get("record_class")
            findings.append(candidate)

    offset_counts = Counter(item["offset"] for item in findings)
    next_header_counts = Counter(
        (item["next_header"], next_header_name(item["next_header"])) for item in findings
    )
    address_pairs = Counter(
        (item["ipv6_source"], item["ipv6_destination"]) for item in findings
    )

    displayed = findings[:args.limit] if args.limit else findings

    for item in displayed:
        preview = item["preview"][:args.preview].hex(" ")
        print()
        print(
            f"packet={item['packet_number']} timestamp={item['timestamp']} "
            f"container_offset={item['offset']} frame_length={item['frame_length']}"
        )
        print(f"  ethernet: {item['source_mac']} -> {item['destination_mac']}")
        print(f"  ipv6: {item['ipv6_source']} -> {item['ipv6_destination']}")
        print(
            f"  next_header={item['next_header']} "
            f"({next_header_name(item['next_header'])}) "
            f"payload_length={item['payload_length']} hop_limit={item['hop_limit']}"
        )
        print(f"  preview={preview}")

    print()
    print("=" * 72)
    print("IPv6 IoTecha container layout inspection summary")
    print("=" * 72)
    print(f"PCAP                     : {args.pcap}")
    print(f"Last SLAC_MATCH.CNF      : {match_packet if match_packet is not None else 'not found'}")
    print(f"Scan start packet        : {start_packet}")
    print(f"Scan end packet          : {end_packet if end_packet is not None else 'end of capture'}")
    print(f"Records scanned          : {scanned_records}")
    print(f"Raw 0x86DD matches       : {raw_matches}")
    print(f"Validated IPv6 candidates: {len(findings)}")
    print(f"Displayed candidates     : {len(displayed)}")

    print()
    print("Validated offsets:")
    if offset_counts:
        for offset, count in offset_counts.most_common():
            print(f"  {offset:<8} {count}")
    else:
        print("  none")

    print()
    print("Next-header distribution:")
    if next_header_counts:
        for (number, name), count in next_header_counts.most_common():
            print(f"  {number:<4} {name:<22} {count}")
    else:
        print("  none")

    print()
    print("IPv6 address relationships:")
    if address_pairs:
        for (source, destination), count in address_pairs.most_common():
            print(f"  {source} -> {destination}  {count}")
    else:
        print("  none")

    print()
    print("Rejected candidates:")
    if rejection_counts:
        for reason, count in rejection_counts.most_common():
            print(f"  {reason:<32} {count}")
    else:
        print("  none")


if __name__ == "__main__":
    main()
