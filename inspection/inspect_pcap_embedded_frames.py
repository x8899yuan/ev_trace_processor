from collections import Counter, defaultdict
from pathlib import Path

from readers.pcap_reader import PcapReader


PCAP_FILE = Path(r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap")
TARGET_CLASSES = {
    b"\x02\x01\x93": "HPGP_MEASUREMENT",
    b"\x02\x05\x04": "HPGP_RECORD_020504",
    b"\x02\x05\x06": "HPGP_RECORD_020506",
}
ETHERTYPES = {
    b"\x88\xE1": "HOMEPLUG_AV",
    b"\x86\xDD": "IPv6",
    b"\x08\x00": "IPv4",
    b"\x08\x06": "ARP",
}
V2GTP_VERSIONS = {(0x01, 0xFE), (0x02, 0xFD)}
MAX_EXAMPLES = 8


def mac(data: bytes) -> str:
    return ":".join(f"{value:02x}" for value in data)


def hex_bytes(data: bytes) -> str:
    return " ".join(f"{value:02X}" for value in data)


def scan_ethertypes(data: bytes) -> list[tuple[int, str]]:
    results = []
    for marker, name in ETHERTYPES.items():
        start = 0
        while True:
            offset = data.find(marker, start)
            if offset < 0:
                break
            results.append((offset, name))
            start = offset + 1
    return results


def scan_ethernet_frames(data: bytes) -> list[dict]:
    results = []
    for offset in range(max(0, len(data) - 13)):
        ether_type = data[offset + 12:offset + 14]
        name = ETHERTYPES.get(ether_type)
        if name is None:
            continue
        results.append(
            {
                "offset": offset,
                "dst_mac": mac(data[offset:offset + 6]),
                "src_mac": mac(data[offset + 6:offset + 12]),
                "ether_type": name,
            }
        )
    return results


def scan_ipv6(data: bytes) -> list[dict]:
    results = []
    for offset in range(max(0, len(data) - 39)):
        if data[offset] >> 4 != 6:
            continue
        payload_length = int.from_bytes(data[offset + 4:offset + 6], "big")
        next_header = data[offset + 6]
        hop_limit = data[offset + 7]
        if next_header not in (6, 17, 58) or hop_limit == 0:
            continue
        if offset + 40 + payload_length > len(data):
            continue
        results.append(
            {
                "offset": offset,
                "payload_length": payload_length,
                "next_header": next_header,
                "hop_limit": hop_limit,
            }
        )
    return results


def scan_ports(data: bytes, port: int) -> list[int]:
    marker = port.to_bytes(2, "big")
    offsets = []
    start = 0
    while True:
        offset = data.find(marker, start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + 1
    return offsets


def scan_v2gtp(data: bytes) -> list[dict]:
    results = []
    for offset in range(max(0, len(data) - 7)):
        version = data[offset]
        inverse = data[offset + 1]
        if (version, inverse) not in V2GTP_VERSIONS:
            continue
        payload_type = int.from_bytes(data[offset + 2:offset + 4], "big")
        payload_length = int.from_bytes(data[offset + 4:offset + 8], "big")
        if payload_length > len(data) - offset - 8:
            continue
        results.append(
            {
                "offset": offset,
                "version": version,
                "inverse": inverse,
                "payload_type": payload_type,
                "payload_length": payload_length,
            }
        )
    return results


def scan_homeplug_headers(data: bytes) -> list[dict]:
    results = []
    for offset in range(max(0, len(data) - 4)):
        mmv = data[offset]
        if mmv not in (0x00, 0x01, 0x02):
            continue
        mmtype = int.from_bytes(data[offset + 1:offset + 3], "little")
        if not 0x6000 <= mmtype <= 0x60FF:
            continue
        results.append({"offset": offset, "mmv": mmv, "mmtype": mmtype})
    return results


def main() -> None:
    trace = PcapReader().read(PCAP_FILE)
    class_counts = Counter()
    ethertype_hits = Counter()
    ethernet_hits = Counter()
    ipv6_hits = Counter()
    port_hits = Counter()
    v2gtp_hits = Counter()
    homeplug_hits = Counter()
    examples = defaultdict(list)

    for index, event in enumerate(trace.events):
        payload = event.payload
        if payload.get("protocol") != "HOMEPLUG_AV":
            continue
        data = payload.get("ethernet_payload")
        if not isinstance(data, bytes) or len(data) < 19:
            continue

        record_class = data[16:19]
        class_name = TARGET_CLASSES.get(record_class)
        if class_name is None:
            continue

        class_counts[class_name] += 1

        for offset, name in scan_ethertypes(data):
            ethertype_hits[(class_name, name, offset)] += 1

        for frame in scan_ethernet_frames(data):
            key = (
                class_name,
                frame["ether_type"],
                frame["offset"],
                frame["src_mac"],
                frame["dst_mac"],
            )
            ethernet_hits[key] += 1
            if len(examples[("ethernet", key)]) < MAX_EXAMPLES:
                examples[("ethernet", key)].append(index)

        for candidate in scan_ipv6(data):
            key = (
                class_name,
                candidate["offset"],
                candidate["next_header"],
            )
            ipv6_hits[key] += 1

        for port in (15118, 13400):
            for offset in scan_ports(data, port):
                port_hits[(class_name, port, offset)] += 1

        for candidate in scan_v2gtp(data):
            key = (
                class_name,
                candidate["offset"],
                candidate["payload_type"],
                candidate["payload_length"],
            )
            v2gtp_hits[key] += 1
            if len(examples[("v2gtp", key)]) < MAX_EXAMPLES:
                examples[("v2gtp", key)].append(index)

        for candidate in scan_homeplug_headers(data):
            key = (
                class_name,
                candidate["offset"],
                candidate["mmv"],
                candidate["mmtype"],
            )
            homeplug_hits[key] += 1

    print("File:", PCAP_FILE)
    print("Packets:", trace.event_count)
    print()

    print("Target IoTecha record classes")
    for name, count in class_counts.most_common():
        print(f"  {name}: {count:,}")

    print()
    print("Embedded EtherType byte-pattern hits")
    if ethertype_hits:
        for (class_name, name, offset), count in ethertype_hits.most_common(40):
            print(f"  {class_name} | {name} | offset={offset} | count={count:,}")
    else:
        print("  None")

    print()
    print("Candidate embedded Ethernet frames")
    if ethernet_hits:
        for key, count in ethernet_hits.most_common(30):
            class_name, ether_type, offset, src, dst = key
            print(
                f"  {class_name} | offset={offset} | {src} -> {dst} | "
                f"{ether_type} | count={count:,} | packets={examples[('ethernet', key)]}"
            )
    else:
        print("  None")

    print()
    print("Candidate embedded IPv6 headers")
    if ipv6_hits:
        for (class_name, offset, next_header), count in ipv6_hits.most_common(30):
            protocol = {6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(next_header, str(next_header))
            print(
                f"  {class_name} | offset={offset} | next={protocol} | count={count:,}"
            )
    else:
        print("  None")

    print()
    print("Port byte-pattern hits")
    if port_hits:
        for (class_name, port, offset), count in port_hits.most_common(30):
            print(f"  {class_name} | port={port} | offset={offset} | count={count:,}")
    else:
        print("  None")

    print()
    print("V2GTP header candidates")
    if v2gtp_hits:
        for key, count in v2gtp_hits.most_common(30):
            class_name, offset, payload_type, payload_length = key
            print(
                f"  {class_name} | offset={offset} | type=0x{payload_type:04X} | "
                f"length={payload_length} | count={count:,} | packets={examples[('v2gtp', key)]}"
            )
    else:
        print("  None")

    print()
    print("HomePlug MMV/MMTYPE candidates")
    if homeplug_hits:
        for (class_name, offset, mmv, mmtype), count in homeplug_hits.most_common(50):
            print(
                f"  {class_name} | offset={offset} | MMV=0x{mmv:02X} | "
                f"MMTYPE=0x{mmtype:04X} | count={count:,}"
            )
    else:
        print("  None")

    print()
    print("Interpretation guardrails")
    print("  Pattern hits are candidates until structural consistency is established.")
    print("  MAC/IP/port patterns are not promoted to ECU identity by this script.")
    print("  No certificate material is extracted or printed by this script.")


if __name__ == "__main__":
    main()
