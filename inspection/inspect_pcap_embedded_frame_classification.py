import argparse
from collections import Counter
from pathlib import Path

import dpkt

from services.iotecha_embedded_frame_classifier import (
    EmbeddedProtocol,
    IoTechaEmbeddedFrameClassifier,
)


DEFAULT_PCAP = Path(
    r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap"
)

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_HOMEPLUG = 0x88E1
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

KNOWN_ETHERTYPES = {
    ETHERTYPE_IPV4,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV6,
    ETHERTYPE_HOMEPLUG,
    ETHERTYPE_VLAN,
    ETHERTYPE_QINQ,
}

OUTER_IOTECHA_MMTYPE = 0xA214

SUPPORTED_HOMEPLUG_MMV = {
    0x00,
    0x01,
}

SLAC_MINIMUM_LENGTHS = {
    0x6064: 19,
    0x6065: 25,
    0x6068: 19,
    0x606C: 52,
    0x606E: 20,
    0x606F: 50,
    0x6070: 19,
    0x6074: 62,
    0x6075: 62,
}


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "pcap",
        nargs="?",
        type=Path,
        default=DEFAULT_PCAP,
    )

    parser.add_argument(
        "--packet",
        type=int,
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=0,
    )

    parser.add_argument(
        "--preview",
        type=int,
        default=32,
    )

    parser.add_argument(
        "--show-rejected",
        action="store_true",
    )

    parser.add_argument(
        "--include-outer",
        action="store_true",
    )

    return parser.parse_args()


def evidence_dict(result):
    return {
        item.pattern: item.value
        for item in result.evidence
    }


def validate_mac(mac):
    if len(mac) != 6:
        return False

    if mac == b"\x00" * 6:
        return False

    return True


def parse_ethernet_header(data, offset):
    if offset < 0:
        return None

    if offset + 14 > len(data):
        return None

    destination = data[offset:offset + 6]
    source = data[offset + 6:offset + 12]

    if not validate_mac(destination):
        return None

    if not validate_mac(source):
        return None

    ethertype = int.from_bytes(
        data[offset + 12:offset + 14],
        "big",
    )

    payload_offset = offset + 14

    if ethertype in {
        ETHERTYPE_VLAN,
        ETHERTYPE_QINQ,
    }:
        if payload_offset + 4 > len(data):
            return None

        ethertype = int.from_bytes(
            data[payload_offset + 2:payload_offset + 4],
            "big",
        )

        payload_offset += 4

    return {
        "destination": destination,
        "source": source,
        "ethertype": ethertype,
        "payload_offset": payload_offset,
    }


def validate_ipv4(data, payload_offset):
    available = len(data) - payload_offset

    if available < 20:
        return False, "ipv4_too_short", None

    first_byte = data[payload_offset]

    version = first_byte >> 4
    ihl = first_byte & 0x0F

    if version != 4:
        return False, "ipv4_invalid_version", None

    if ihl < 5:
        return False, "ipv4_invalid_ihl", None

    header_length = ihl * 4

    if available < header_length:
        return False, "ipv4_header_truncated", None

    total_length = int.from_bytes(
        data[payload_offset + 2:payload_offset + 4],
        "big",
    )

    if total_length < header_length:
        return False, "ipv4_invalid_total_length", None

    if total_length > available:
        return False, "ipv4_total_length_exceeds_available", None

    header = data[
        payload_offset:payload_offset + header_length
    ]

    if ipv4_checksum(header) != 0:
        return False, "ipv4_invalid_checksum", None

    return True, "ipv4_valid", total_length


def ipv4_checksum(data):
    if len(data) % 2:
        data += b"\x00"

    total = 0

    for index in range(0, len(data), 2):
        total += (
            data[index] << 8
        ) + data[index + 1]

        total = (
            total & 0xFFFF
        ) + (
            total >> 16
        )

    total = (
        total & 0xFFFF
    ) + (
        total >> 16
    )

    return total & 0xFFFF


def validate_arp(data, payload_offset):
    available = len(data) - payload_offset

    if available < 28:
        return False, "arp_too_short", None

    hardware_type = int.from_bytes(
        data[payload_offset:payload_offset + 2],
        "big",
    )

    protocol_type = int.from_bytes(
        data[payload_offset + 2:payload_offset + 4],
        "big",
    )

    hardware_length = data[payload_offset + 4]
    protocol_length = data[payload_offset + 5]

    operation = int.from_bytes(
        data[payload_offset + 6:payload_offset + 8],
        "big",
    )

    if hardware_type != 0x0001:
        return False, "arp_invalid_hardware_type", None

    if protocol_type != ETHERTYPE_IPV4:
        return False, "arp_invalid_protocol_type", None

    if hardware_length != 6:
        return False, "arp_invalid_hardware_length", None

    if protocol_length != 4:
        return False, "arp_invalid_protocol_length", None

    if operation not in {1, 2}:
        return False, "arp_invalid_operation", None

    return True, "arp_valid", 28


def validate_ipv6(data, payload_offset):
    available = len(data) - payload_offset

    if available < 40:
        return False, "ipv6_too_short", None

    version = data[payload_offset] >> 4

    if version != 6:
        return False, "ipv6_invalid_version", None

    payload_length = int.from_bytes(
        data[payload_offset + 4:payload_offset + 6],
        "big",
    )

    total_length = 40 + payload_length

    if total_length > available:
        return False, "ipv6_payload_exceeds_available", None

    return True, "ipv6_valid", total_length


def validate_homeplug(data, payload_offset):
    available = len(data) - payload_offset

    if available < 3:
        return False, "homeplug_too_short", None

    mmv = data[payload_offset]

    if mmv not in SUPPORTED_HOMEPLUG_MMV:
        return False, "homeplug_invalid_mmv", None

    mmtype = int.from_bytes(
        data[payload_offset + 1:payload_offset + 3],
        "little",
    )

    minimum_length = SLAC_MINIMUM_LENGTHS.get(mmtype)

    if (
        minimum_length is not None
        and available < minimum_length
    ):
        return False, "slac_payload_too_short", mmtype

    return True, "homeplug_valid", mmtype


def validate_candidate(data, offset):
    header = parse_ethernet_header(
        data,
        offset,
    )

    if header is None:
        return False, "invalid_ethernet", None

    ethertype = header["ethertype"]
    payload_offset = header["payload_offset"]

    if ethertype == ETHERTYPE_IPV4:
        valid, reason, length = validate_ipv4(
            data,
            payload_offset,
        )

    elif ethertype == ETHERTYPE_ARP:
        valid, reason, length = validate_arp(
            data,
            payload_offset,
        )

    elif ethertype == ETHERTYPE_IPV6:
        valid, reason, length = validate_ipv6(
            data,
            payload_offset,
        )

    elif ethertype == ETHERTYPE_HOMEPLUG:
        valid, reason, length = validate_homeplug(
            data,
            payload_offset,
        )

    else:
        return False, "unsupported_ethertype", None

    return valid, reason, {
        "ethertype": ethertype,
        "payload_offset": payload_offset,
        "detail": length,
    }


def find_candidates(data):
    if len(data) < 14:
        return

    maximum_offset = len(data) - 14

    for offset in range(maximum_offset + 1):
        ethertype = int.from_bytes(
            data[offset + 12:offset + 14],
            "big",
        )

        if ethertype not in KNOWN_ETHERTYPES:
            continue

        yield offset


def is_outer_iotecha_frame(
    data,
    offset,
):
    if offset != 0:
        return False

    header = parse_ethernet_header(
        data,
        offset,
    )

    if header is None:
        return False

    if header["ethertype"] != ETHERTYPE_HOMEPLUG:
        return False

    payload_offset = header["payload_offset"]

    if len(data) < payload_offset + 3:
        return False

    mmtype = int.from_bytes(
        data[payload_offset + 1:payload_offset + 3],
        "little",
    )

    return mmtype == OUTER_IOTECHA_MMTYPE


def validated_frame_length(
    data,
    offset,
    validation,
):
    ethertype = validation["ethertype"]
    payload_offset = validation["payload_offset"]
    detail = validation["detail"]

    ethernet_header_length = (
        payload_offset - offset
    )

    if ethertype in {
        ETHERTYPE_IPV4,
        ETHERTYPE_ARP,
        ETHERTYPE_IPV6,
    }:
        return ethernet_header_length + detail

    return len(data) - offset


def inspect_packet(
    packet_number,
    timestamp,
    packet,
    classifier,
    preview_length,
    include_outer,
    show_rejected,
    rejection_counts,
):
    findings = []

    data = bytes(packet)

    for offset in find_candidates(data):
        if (
            not include_outer
            and is_outer_iotecha_frame(
                data,
                offset,
            )
        ):
            continue

        valid, reason, validation = (
            validate_candidate(
                data,
                offset,
            )
        )

        if not valid:
            rejection_counts[reason] += 1

            if show_rejected:
                print(
                    f"REJECT packet={packet_number} "
                    f"offset={offset} "
                    f"reason={reason}"
                )

            continue

        frame_length = validated_frame_length(
            data,
            offset,
            validation,
        )

        frame = data[
            offset:offset + frame_length
        ]

        classification = classifier.classify(
            frame,
            offset=offset,
        )

        evidence = evidence_dict(
            classification
        )

        findings.append(
            {
                "packet": packet_number,
                "timestamp": timestamp,
                "offset": offset,
                "length": frame_length,
                "protocol": (
                    classification.protocol.value
                ),
                "subtype": (
                    classification.subtype or ""
                ),
                "confidence": (
                    classification.confidence
                ),
                "ethertype": (
                    evidence.get(
                        "inner_ethertype"
                    )
                    or evidence.get(
                        "ethertype"
                    )
                    or ""
                ),
                "mmv": evidence.get(
                    "homeplug_mmv",
                    "",
                ),
                "mmtype": evidence.get(
                    "homeplug_mmtype",
                    "",
                ),
                "preview": frame[
                    :preview_length
                ].hex(" "),
            }
        )

    return findings


def print_finding(finding):
    marker = ""

    if finding["protocol"] == "slac":
        marker = " [SLAC]"

    print(
        f"packet={finding['packet']} "
        f"offset={finding['offset']} "
        f"protocol={finding['protocol']} "
        f"mmtype={finding['mmtype'] or '-'} "
        f"subtype={finding['subtype'] or '-'}"
        f"{marker}"
    )

    print(
        f"  ethertype="
        f"{finding['ethertype'] or '-'} "
        f"length={finding['length']} "
        f"confidence="
        f"{finding['confidence']:.2f}"
    )

    print(
        f"  preview={finding['preview']}"
    )


def open_pcap(path):
    handle = path.open("rb")

    try:
        reader = dpkt.pcap.Reader(handle)
        return handle, reader
    except (
        ValueError,
        dpkt.dpkt.NeedData,
    ):
        handle.seek(0)

    try:
        reader = dpkt.pcapng.Reader(handle)
        return handle, reader
    except Exception:
        handle.close()
        raise


def main():
    args = parse_args()

    if not args.pcap.exists():
        raise SystemExit(
            f"PCAP file not found: {args.pcap}"
        )

    if args.preview < 0:
        raise SystemExit(
            "--preview cannot be negative"
        )

    if args.limit < 0:
        raise SystemExit(
            "--limit cannot be negative"
        )

    classifier = IoTechaEmbeddedFrameClassifier()

    protocol_counts = Counter()
    subtype_counts = Counter()
    mmtype_counts = Counter()
    rejection_counts = Counter()

    packets_read = 0
    packets_inspected = 0
    findings_count = 0
    packets_with_findings = set()
    raw_candidate_count = 0

    handle, reader = open_pcap(
        args.pcap
    )

    try:
        for packet_number, (
            timestamp,
            packet,
        ) in enumerate(
            reader,
            start=1,
        ):
            packets_read += 1

            if (
                args.packet is not None
                and packet_number
                != args.packet
            ):
                continue

            packets_inspected += 1

            data = bytes(packet)

            raw_offsets = list(
                find_candidates(data)
            )

            raw_candidate_count += len(
                raw_offsets
            )

            findings = inspect_packet(
                packet_number=packet_number,
                timestamp=timestamp,
                packet=packet,
                classifier=classifier,
                preview_length=args.preview,
                include_outer=args.include_outer,
                show_rejected=args.show_rejected,
                rejection_counts=rejection_counts,
            )

            for finding in findings:
                print_finding(finding)

                findings_count += 1

                packets_with_findings.add(
                    packet_number
                )

                protocol_counts[
                    finding["protocol"]
                ] += 1

                if finding["subtype"]:
                    subtype_counts[
                        finding["subtype"]
                    ] += 1

                if finding["mmtype"]:
                    mmtype_counts[
                        finding["mmtype"]
                    ] += 1

                if (
                    args.limit
                    and findings_count
                    >= args.limit
                ):
                    break

            if (
                args.limit
                and findings_count
                >= args.limit
            ):
                break

            if (
                args.packet is not None
                and packet_number
                == args.packet
            ):
                break

    finally:
        handle.close()

    print()
    print("=" * 72)
    print(
        "Structurally validated embedded frame summary"
    )
    print("=" * 72)

    print(
        f"PCAP                   : "
        f"{args.pcap}"
    )
    print(
        f"Packets read           : "
        f"{packets_read}"
    )
    print(
        f"Packets inspected      : "
        f"{packets_inspected}"
    )
    print(
        f"Raw EtherType matches  : "
        f"{raw_candidate_count}"
    )
    print(
        f"Packets with validated : "
        f"{len(packets_with_findings)}"
    )
    print(
        f"Validated findings     : "
        f"{findings_count}"
    )

    print()
    print("Validated protocols:")

    if protocol_counts:
        for protocol, count in (
            protocol_counts.most_common()
        ):
            print(
                f"  {protocol:<12} {count}"
            )
    else:
        print("  none")

    print()
    print("Validated SLAC:")

    slac_found = False

    for subtype, count in (
        subtype_counts.most_common()
    ):
        if subtype.startswith("CM_"):
            slac_found = True

            print(
                f"  {subtype:<28} "
                f"{count}"
            )

    if not slac_found:
        print("  none")

    print()
    print("Validated HomePlug MMTYPEs:")

    if mmtype_counts:
        for mmtype, count in (
            mmtype_counts.most_common()
        ):
            print(
                f"  {mmtype:<12} {count}"
            )
    else:
        print("  none")

    print()
    print("Rejected candidates:")

    if rejection_counts:
        for reason, count in (
            rejection_counts.most_common()
        ):
            print(
                f"  {reason:<36} "
                f"{count}"
            )
    else:
        print("  none")


if __name__ == "__main__":
    main()