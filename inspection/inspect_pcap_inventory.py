from collections import Counter
from pathlib import Path

from readers.pcap_reader import PcapReader


pcap_file = Path(
    r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap"
)

trace = PcapReader().read(pcap_file)

mac_addresses = Counter()
ip_addresses = Counter()
vlans = Counter()
ether_types = Counter()
tcp_ports = Counter()
udp_ports = Counter()
protocols = Counter()
endpoint_pairs = Counter()

homeplug_count = 0
doip_count = 0
someip_candidates = 0
someip_sd_candidates = 0

printable_strings = Counter()
vin_candidates = Counter()


def extract_strings(data: bytes, minimum_length: int = 4) -> list[str]:
    results = []
    current = []

    for value in data:
        if 32 <= value <= 126:
            current.append(chr(value))
        else:
            if len(current) >= minimum_length:
                results.append("".join(current))
            current = []

    if len(current) >= minimum_length:
        results.append("".join(current))

    return results


def looks_like_vin(value: str) -> bool:
    if len(value) != 17:
        return False

    allowed = set("ABCDEFGHJKLMNPRSTUVWXYZ0123456789")
    return all(character in allowed for character in value)


for event in trace.events:
    payload = event.payload

    protocol = payload.get("protocol", "UNKNOWN")
    protocols[protocol] += 1

    src_mac = payload.get("src_mac")
    dst_mac = payload.get("dst_mac")

    if src_mac:
        mac_addresses[src_mac] += 1

    if dst_mac:
        mac_addresses[dst_mac] += 1

    src_ip = payload.get("src_ip")
    dst_ip = payload.get("dst_ip")

    if src_ip:
        ip_addresses[src_ip] += 1

    if dst_ip:
        ip_addresses[dst_ip] += 1

    if src_mac and dst_mac:
        endpoint_pairs[(src_mac, dst_mac)] += 1

    for vlan_id in payload.get("vlan_ids", []):
        vlans[vlan_id] += 1

    ether_type = payload.get("ether_type")

    if isinstance(ether_type, int):
        ether_types[ether_type] += 1

    src_port = payload.get("src_port")
    dst_port = payload.get("dst_port")

    if protocol == "TCP":
        if isinstance(src_port, int):
            tcp_ports[src_port] += 1
        if isinstance(dst_port, int):
            tcp_ports[dst_port] += 1

    if protocol == "UDP":
        if isinstance(src_port, int):
            udp_ports[src_port] += 1
        if isinstance(dst_port, int):
            udp_ports[dst_port] += 1

    if protocol == "HOMEPLUG_AV":
        homeplug_count += 1

    if src_port == 13400 or dst_port == 13400:
        doip_count += 1

    if src_port in (30490, 30500) or dst_port in (30490, 30500):
        someip_sd_candidates += 1

    if isinstance(src_port, int) and 30490 <= src_port <= 30599:
        someip_candidates += 1
    elif isinstance(dst_port, int) and 30490 <= dst_port <= 30599:
        someip_candidates += 1

    data = payload.get("transport_payload")

    if not isinstance(data, bytes):
        data = payload.get("ethernet_payload")

    if not isinstance(data, bytes):
        continue

    for text in extract_strings(data):
        printable_strings[text] += 1

        if looks_like_vin(text):
            vin_candidates[text] += 1

        if len(text) > 17:
            for start in range(len(text) - 16):
                candidate = text[start:start + 17]

                if looks_like_vin(candidate):
                    vin_candidates[candidate] += 1


print("File:", pcap_file)
print("Packets:", trace.event_count)
print("Start:", trace.metadata.start_timestamp)
print("End:", trace.metadata.end_timestamp)
print()

print("Protocols")
for value, count in protocols.most_common():
    print(f"  {value}: {count:,}")

print()
print("EtherTypes")
for value, count in ether_types.most_common():
    print(f"  0x{value:04X}: {count:,}")

print()
print("VLANs")
for value, count in vlans.most_common():
    print(f"  {value}: {count:,}")

print()
print("MAC addresses")
for value, count in mac_addresses.most_common():
    print(f"  {value}: {count:,}")

print()
print("IP addresses")
for value, count in ip_addresses.most_common():
    print(f"  {value}: {count:,}")

print()
print("TCP ports")
for value, count in tcp_ports.most_common(30):
    print(f"  {value}: {count:,}")

print()
print("UDP ports")
for value, count in udp_ports.most_common(30):
    print(f"  {value}: {count:,}")

print()
print("Automotive protocol candidates")
print("  HomePlug AV packets:", homeplug_count)
print("  DoIP port 13400 packets:", doip_count)
print("  SOME/IP-range candidates:", someip_candidates)
print("  SOME/IP-SD candidates:", someip_sd_candidates)

print()
print("Top MAC endpoint pairs")
for (src, dst), count in endpoint_pairs.most_common(20):
    print(f"  {src} -> {dst}: {count:,}")

print()
print("VIN candidates")
if vin_candidates:
    for value, count in vin_candidates.most_common():
        print(f"  {value}: {count:,}")
else:
    print("  None")

print()
print("Representative printable payload strings")
for value, count in printable_strings.most_common(50):
    print(f"  {count:,} | {value}")