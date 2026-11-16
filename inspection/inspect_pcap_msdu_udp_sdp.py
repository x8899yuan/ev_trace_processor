import argparse
from collections import Counter
from ipaddress import IPv6Address
from pathlib import Path

import dpkt


DEFAULT_PCAP = Path(
    r"data\pcap\20250401122302-700006-18-G3-PWR-LOSS-OLD-SOFT-msdu.pcap"
)
ETHERTYPE_IPV6 = 0x86DD
SDP_PORT = 15118
V2GTP_VERSION = 0x01
V2GTP_INVERSE_VERSION = 0xFE
PAYLOAD_TYPE_SDP_REQUEST = 0x9000
PAYLOAD_TYPE_SDP_RESPONSE = 0x9001


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", nargs="?", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--packet", type=int)
    parser.add_argument("--preview", type=int, default=64)
    return parser.parse_args()


def format_mac(value):
    return ":".join(f"{item:02x}" for item in value)


def parse_v2gtp(payload):
    if len(payload) < 8:
        return {"valid": False, "reason": "v2gtp_too_short"}

    version = payload[0]
    inverse_version = payload[1]
    payload_type = int.from_bytes(payload[2:4], "big")
    payload_length = int.from_bytes(payload[4:8], "big")
    available = len(payload) - 8

    if version != V2GTP_VERSION:
        return {"valid": False, "reason": "v2gtp_invalid_version"}
    if inverse_version != V2GTP_INVERSE_VERSION:
        return {"valid": False, "reason": "v2gtp_invalid_inverse_version"}
    if payload_length > available:
        return {"valid": False, "reason": "v2gtp_payload_exceeds_udp"}

    body = payload[8:8 + payload_length]
    result = {
        "valid": True,
        "version": version,
        "inverse_version": inverse_version,
        "payload_type": payload_type,
        "payload_length": payload_length,
        "body": body,
    }

    if payload_type == PAYLOAD_TYPE_SDP_REQUEST:
        result["message_type"] = "SDP_REQUEST"
        if len(body) >= 2:
            result["security_protocol"] = body[0]
            result["transport_protocol"] = body[1]
        else:
            result["sdp_error"] = "request_body_too_short"

    elif payload_type == PAYLOAD_TYPE_SDP_RESPONSE:
        result["message_type"] = "SDP_RESPONSE"
        if len(body) >= 20:
            result["secc_ipv6"] = str(IPv6Address(body[:16]))
            result["secc_port"] = int.from_bytes(body[16:18], "big")
            result["security_protocol"] = body[18]
            result["transport_protocol"] = body[19]
        else:
            result["sdp_error"] = "response_body_too_short"

    else:
        result["message_type"] = f"V2GTP_0x{payload_type:04X}"

    return result


def protocol_name(value, kind):
    if kind == "security":
        return {0x00: "TLS", 0x10: "NO_TLS"}.get(value, f"0x{value:02X}")
    if kind == "transport":
        return {0x00: "TCP", 0x10: "UDP"}.get(value, f"0x{value:02X}")
    return f"0x{value:02X}"


def main():
    args = parse_args()

    if not args.pcap.exists():
        raise SystemExit(f"PCAP file not found: {args.pcap}")
    if args.preview < 0:
        raise SystemExit("--preview cannot be negative")

    udp_frames = []
    v2gtp_counts = Counter()
    rejection_counts = Counter()

    with args.pcap.open("rb") as handle:
        reader = dpkt.pcap.Reader(handle)

        for packet_number, (timestamp, packet) in enumerate(reader, start=1):
            if args.packet is not None and packet_number != args.packet:
                continue

            try:
                ethernet = dpkt.ethernet.Ethernet(packet)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
                continue

            if ethernet.type != ETHERTYPE_IPV6 or not isinstance(ethernet.data, dpkt.ip6.IP6):
                continue

            ipv6 = ethernet.data
            if not isinstance(ipv6.data, dpkt.udp.UDP):
                continue

            udp = ipv6.data
            udp_payload = bytes(udp.data)
            v2gtp = parse_v2gtp(udp_payload)

            if v2gtp["valid"]:
                v2gtp_counts[v2gtp["message_type"]] += 1
            else:
                rejection_counts[v2gtp["reason"]] += 1

            udp_frames.append(
                {
                    "packet": packet_number,
                    "timestamp": timestamp,
                    "src_mac": format_mac(ethernet.src),
                    "dst_mac": format_mac(ethernet.dst),
                    "src_ipv6": str(IPv6Address(ipv6.src)),
                    "dst_ipv6": str(IPv6Address(ipv6.dst)),
                    "src_port": udp.sport,
                    "dst_port": udp.dport,
                    "udp_length": udp.ulen,
                    "udp_payload": udp_payload,
                    "v2gtp": v2gtp,
                }
            )

    for item in udp_frames:
        v2gtp = item["v2gtp"]

        print()
        print(f"packet={item['packet']} timestamp={item['timestamp']:.6f}")
        print(f"  ethernet: {item['src_mac']} -> {item['dst_mac']}")
        print(f"  ipv6: {item['src_ipv6']} -> {item['dst_ipv6']}")
        print(
            f"  udp: {item['src_port']} -> {item['dst_port']} "
            f"length={item['udp_length']}"
        )

        if v2gtp["valid"]:
            print(
                f"  v2gtp: version=0x{v2gtp['version']:02X} "
                f"inverse=0x{v2gtp['inverse_version']:02X} "
                f"payload_type=0x{v2gtp['payload_type']:04X} "
                f"payload_length={v2gtp['payload_length']} "
                f"type={v2gtp['message_type']}"
            )

            if "security_protocol" in v2gtp:
                security = v2gtp["security_protocol"]
                print(
                    f"  security_protocol=0x{security:02X} "
                    f"({protocol_name(security, 'security')})"
                )

            if "transport_protocol" in v2gtp:
                transport = v2gtp["transport_protocol"]
                print(
                    f"  transport_protocol=0x{transport:02X} "
                    f"({protocol_name(transport, 'transport')})"
                )

            if "secc_ipv6" in v2gtp:
                print(f"  secc_ipv6={v2gtp['secc_ipv6']}")
                print(f"  secc_port={v2gtp['secc_port']}")

            if "sdp_error" in v2gtp:
                print(f"  sdp_error={v2gtp['sdp_error']}")
        else:
            print(f"  v2gtp: rejected reason={v2gtp['reason']}")

        print(f"  udp_payload={item['udp_payload'][:args.preview].hex(' ')}")

    print()
    print("=" * 72)
    print("MSDU IPv6 UDP / SDP inspection summary")
    print("=" * 72)
    print(f"PCAP                  : {args.pcap}")
    print(f"IPv6 UDP packets      : {len(udp_frames)}")
    print(f"Valid V2GTP packets   : {sum(v2gtp_counts.values())}")

    print()
    print("V2GTP/SDP message types:")
    if v2gtp_counts:
        for name, count in v2gtp_counts.most_common():
            print(f"  {name:<24} {count}")
    else:
        print("  none")

    print()
    print("Rejected UDP payloads:")
    if rejection_counts:
        for reason, count in rejection_counts.most_common():
            print(f"  {reason:<32} {count}")
    else:
        print("  none")

    print()
    print("SDP endpoints:")
    endpoints = [
        item["v2gtp"]
        for item in udp_frames
        if item["v2gtp"].get("message_type") == "SDP_RESPONSE"
        and "secc_ipv6" in item["v2gtp"]
    ]
    if endpoints:
        for endpoint in endpoints:
            print(
                f"  {endpoint['secc_ipv6']}:{endpoint['secc_port']} "
                f"security={protocol_name(endpoint['security_protocol'], 'security')} "
                f"transport={protocol_name(endpoint['transport_protocol'], 'transport')}"
            )
    else:
        print("  none")


if __name__ == "__main__":
    main()
