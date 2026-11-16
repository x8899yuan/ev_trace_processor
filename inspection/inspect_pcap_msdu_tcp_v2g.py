import argparse
from collections import Counter, defaultdict
from ipaddress import IPv6Address
from pathlib import Path

import dpkt


DEFAULT_PCAP = Path(r"data\pcap\20250401122302-700006-18-G3-PWR-LOSS-OLD-SOFT-msdu.pcap")
DEFAULT_SECC_IPV6 = "fe80::161f:baff:fe10:c9aa"
DEFAULT_SECC_PORT = 63332
ETHERTYPE_IPV6 = 0x86DD
V2GTP_VERSION = 0x01
V2GTP_INVERSE_VERSION = 0xFE


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", nargs="?", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--secc-ipv6", default=DEFAULT_SECC_IPV6)
    parser.add_argument("--secc-port", type=int, default=DEFAULT_SECC_PORT)
    parser.add_argument("--limit", type=int, default=80)
    parser.add_argument("--preview", type=int, default=48)
    return parser.parse_args()


def format_mac(value):
    return ":".join(f"{item:02x}" for item in value)


def tcp_flags(tcp):
    names = []
    for bit, name in (
        (dpkt.tcp.TH_SYN, "SYN"),
        (dpkt.tcp.TH_ACK, "ACK"),
        (dpkt.tcp.TH_PUSH, "PSH"),
        (dpkt.tcp.TH_FIN, "FIN"),
        (dpkt.tcp.TH_RST, "RST"),
    ):
        if tcp.flags & bit:
            names.append(name)
    return ",".join(names) if names else "NONE"


def tls_signature(payload):
    if len(payload) < 5:
        return None
    content_type = payload[0]
    major = payload[1]
    minor = payload[2]
    length = int.from_bytes(payload[3:5], "big")
    if content_type not in {20, 21, 22, 23}:
        return None
    if major != 3 or minor not in {0, 1, 2, 3, 4}:
        return None
    if length > len(payload) - 5:
        return None
    return {
        "content_type": content_type,
        "version": f"3.{minor}",
        "record_length": length,
    }


def parse_v2gtp_messages(payload):
    messages = []
    offset = 0
    while offset + 8 <= len(payload):
        if payload[offset] != V2GTP_VERSION or payload[offset + 1] != V2GTP_INVERSE_VERSION:
            break
        payload_type = int.from_bytes(payload[offset + 2:offset + 4], "big")
        payload_length = int.from_bytes(payload[offset + 4:offset + 8], "big")
        end = offset + 8 + payload_length
        if end > len(payload):
            messages.append(
                {
                    "offset": offset,
                    "payload_type": payload_type,
                    "payload_length": payload_length,
                    "complete": False,
                    "available": len(payload) - offset - 8,
                }
            )
            break
        messages.append(
            {
                "offset": offset,
                "payload_type": payload_type,
                "payload_length": payload_length,
                "complete": True,
                "body": payload[offset + 8:end],
            }
        )
        offset = end
    return messages


def payload_type_name(value):
    names = {
        0x8001: "EXI_ENCODED_V2G_MESSAGE",
        0x8002: "SDP_REQUEST",
        0x8003: "SDP_RESPONSE",
        0x9000: "SDP_REQUEST",
        0x9001: "SDP_RESPONSE",
    }
    return names.get(value, f"0x{value:04X}")


def flow_key(src_ip, src_port, dst_ip, dst_port):
    left = (src_ip, src_port)
    right = (dst_ip, dst_port)
    return tuple(sorted((left, right)))


def main():
    args = parse_args()

    if not args.pcap.exists():
        raise SystemExit(f"PCAP file not found: {args.pcap}")
    if not 1 <= args.secc_port <= 65535:
        raise SystemExit("--secc-port must be between 1 and 65535")
    if args.limit < 0 or args.preview < 0:
        raise SystemExit("--limit and --preview cannot be negative")

    secc_ipv6 = str(IPv6Address(args.secc_ipv6))
    packets = []
    flow_counts = Counter()
    direction_counts = Counter()
    flag_counts = Counter()
    v2gtp_type_counts = Counter()
    tls_counts = Counter()
    payload_packets = 0
    total_payload_bytes = 0
    incomplete_v2gtp = 0

    with args.pcap.open("rb") as handle:
        reader = dpkt.pcap.Reader(handle)

        for packet_number, (timestamp, packet) in enumerate(reader, start=1):
            try:
                ethernet = dpkt.ethernet.Ethernet(packet)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
                continue

            if ethernet.type != ETHERTYPE_IPV6 or not isinstance(ethernet.data, dpkt.ip6.IP6):
                continue

            ipv6 = ethernet.data
            if not isinstance(ipv6.data, dpkt.tcp.TCP):
                continue

            src_ip = str(IPv6Address(ipv6.src))
            dst_ip = str(IPv6Address(ipv6.dst))
            tcp = ipv6.data

            if not (
                (src_ip == secc_ipv6 and tcp.sport == args.secc_port)
                or (dst_ip == secc_ipv6 and tcp.dport == args.secc_port)
            ):
                continue

            payload = bytes(tcp.data)
            flags = tcp_flags(tcp)
            direction = "SECC_TO_EV" if src_ip == secc_ipv6 and tcp.sport == args.secc_port else "EV_TO_SECC"
            key = flow_key(src_ip, tcp.sport, dst_ip, tcp.dport)
            flow_counts[key] += 1
            direction_counts[direction] += 1
            flag_counts[flags] += 1

            tls = tls_signature(payload)
            if tls:
                tls_counts[(tls["content_type"], tls["version"])] += 1

            v2gtp_messages = parse_v2gtp_messages(payload)
            for message in v2gtp_messages:
                if message["complete"]:
                    v2gtp_type_counts[message["payload_type"]] += 1
                else:
                    incomplete_v2gtp += 1

            if payload:
                payload_packets += 1
                total_payload_bytes += len(payload)

            packets.append(
                {
                    "packet": packet_number,
                    "timestamp": timestamp,
                    "src_mac": format_mac(ethernet.src),
                    "dst_mac": format_mac(ethernet.dst),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": tcp.sport,
                    "dst_port": tcp.dport,
                    "flags": flags,
                    "seq": tcp.seq,
                    "ack": tcp.ack,
                    "payload": payload,
                    "direction": direction,
                    "tls": tls,
                    "v2gtp": v2gtp_messages,
                }
            )

    displayed = packets[:args.limit] if args.limit else packets

    for item in displayed:
        print()
        print(
            f"packet={item['packet']} timestamp={item['timestamp']:.6f} "
            f"direction={item['direction']}"
        )
        print(f"  ethernet: {item['src_mac']} -> {item['dst_mac']}")
        print(
            f"  tcp: [{item['src_ip']}]:{item['src_port']} -> "
            f"[{item['dst_ip']}]:{item['dst_port']} "
            f"flags={item['flags']} seq={item['seq']} ack={item['ack']} "
            f"payload={len(item['payload'])}"
        )

        if item["tls"]:
            print(
                f"  tls_signature: content_type={item['tls']['content_type']} "
                f"version={item['tls']['version']} "
                f"record_length={item['tls']['record_length']}"
            )

        if item["v2gtp"]:
            for message in item["v2gtp"]:
                status = "complete" if message["complete"] else "incomplete"
                print(
                    f"  v2gtp: offset={message['offset']} "
                    f"type=0x{message['payload_type']:04X} "
                    f"({payload_type_name(message['payload_type'])}) "
                    f"length={message['payload_length']} status={status}"
                )

        if item["payload"]:
            print(f"  preview={item['payload'][:args.preview].hex(' ')}")

    print()
    print("=" * 72)
    print("MSDU TCP / V2G inspection summary")
    print("=" * 72)
    print(f"PCAP                    : {args.pcap}")
    print(f"SECC endpoint           : [{secc_ipv6}]:{args.secc_port}")
    print(f"Matching TCP packets    : {len(packets)}")
    print(f"TCP packets with payload: {payload_packets}")
    print(f"TCP payload bytes       : {total_payload_bytes}")
    print(f"TLS-like records        : {sum(tls_counts.values())}")
    print(f"Complete V2GTP messages : {sum(v2gtp_type_counts.values())}")
    print(f"Incomplete V2GTP starts : {incomplete_v2gtp}")

    print()
    print("TCP directions:")
    if direction_counts:
        for direction, count in direction_counts.most_common():
            print(f"  {direction:<16} {count}")
    else:
        print("  none")

    print()
    print("TCP flag combinations:")
    if flag_counts:
        for flags, count in flag_counts.most_common():
            print(f"  {flags:<16} {count}")
    else:
        print("  none")

    print()
    print("TCP flows:")
    if flow_counts:
        for key, count in flow_counts.most_common():
            left, right = key
            print(f"  [{left[0]}]:{left[1]} <-> [{right[0]}]:{right[1]}  {count}")
    else:
        print("  none")

    print()
    print("V2GTP payload types:")
    if v2gtp_type_counts:
        for payload_type, count in v2gtp_type_counts.most_common():
            print(
                f"  0x{payload_type:04X} "
                f"{payload_type_name(payload_type):<28} {count}"
            )
    else:
        print("  none")

    print()
    print("TLS-like signatures:")
    if tls_counts:
        for (content_type, version), count in tls_counts.most_common():
            print(f"  content_type={content_type} version={version}  {count}")
    else:
        print("  none")


if __name__ == "__main__":
    main()
