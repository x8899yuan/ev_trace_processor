import argparse
from collections import Counter
from pathlib import Path

from readers.pcap_reader import PcapReader
from services.iotecha_hpgp_decoder_service import IotechaHpgpDecoderService


DEFAULT_PCAP = Path(r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", nargs="?", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--packet", type=int)
    parser.add_argument("--next-header", type=int)
    parser.add_argument("--limit", type=int, default=0)
    return parser.parse_args()


def collect_ipv6_frames(records, packet_filter=None, next_header_filter=None):
    frames = []

    for record in records:
        packet_index = record.get("packet_index")
        packet_number = packet_index + 1 if isinstance(packet_index, int) else None

        if packet_filter is not None and packet_number != packet_filter:
            continue

        for frame in record.get("embedded_frames", []):
            if frame.get("protocol") != "ipv6":
                continue

            if next_header_filter is not None and frame.get("next_header") != next_header_filter:
                continue

            frames.append(
                {
                    "packet_number": packet_number,
                    "timestamp": record.get("timestamp"),
                    "record_class": record.get("record_class"),
                    "frame": frame,
                }
            )

    frames.sort(
        key=lambda item: (
            item["packet_number"] if item["packet_number"] is not None else -1
        )
    )

    return frames


def print_frame(item):
    frame = item["frame"]

    print()
    print(
        f"packet={item['packet_number']} "
        f"timestamp={item['timestamp']} "
        f"payload_offset={frame['offset']} "
        f"packet_offset={frame['packet_offset']}"
    )
    print(
        f"  ethernet: {frame['source_mac']} -> {frame['destination_mac']} "
        f"ethertype={frame['ethertype']}"
    )
    print(
        f"  ipv6: {frame['ipv6_source']} -> {frame['ipv6_destination']}"
    )
    print(
        f"  next_header={frame['next_header']} "
        f"subtype={frame['subtype']} "
        f"hop_limit={frame['hop_limit']}"
    )
    print(
        f"  ipv6_payload_length={frame['ipv6_payload_length']} "
        f"frame_length={frame['captured_length']} "
        f"boundary={frame['boundary_source']}"
    )
    print(
        f"  record_class={item['record_class']} "
        f"sha256={frame['sha256']}"
    )


def print_counter(title, counter):
    print()
    print(title)

    if not counter:
        print("  none")
        return

    for key, count in counter.most_common():
        print(f"  {str(key):<28} {count}")


def main():
    args = parse_args()

    if not args.pcap.exists():
        raise SystemExit(f"PCAP file not found: {args.pcap}")

    if args.limit < 0:
        raise SystemExit("--limit cannot be negative")

    if args.next_header is not None and not 0 <= args.next_header <= 255:
        raise SystemExit("--next-header must be between 0 and 255")

    trace = PcapReader().read(args.pcap)
    service = IotechaHpgpDecoderService()
    records = service.decode_trace(trace)

    all_ipv6_frames = collect_ipv6_frames(records)
    frames = collect_ipv6_frames(
        records,
        packet_filter=args.packet,
        next_header_filter=args.next_header,
    )

    shown = frames[:args.limit] if args.limit else frames

    for item in shown:
        print_frame(item)

    next_header_counts = Counter(
        (item["frame"]["next_header"], item["frame"]["subtype"])
        for item in all_ipv6_frames
    )
    source_counts = Counter(
        item["frame"]["ipv6_source"]
        for item in all_ipv6_frames
    )
    destination_counts = Counter(
        item["frame"]["ipv6_destination"]
        for item in all_ipv6_frames
    )
    mac_pairs = Counter(
        (item["frame"]["source_mac"], item["frame"]["destination_mac"])
        for item in all_ipv6_frames
    )

    print()
    print("=" * 72)
    print("Recovered IPv6 frame inspection summary")
    print("=" * 72)
    print(f"PCAP                  : {args.pcap}")
    print(f"Decoded records       : {len(records)}")
    print(f"Validated IPv6 frames : {len(all_ipv6_frames)}")
    print(f"Matching filter       : {len(frames)}")
    print(f"Displayed frames      : {len(shown)}")

    print_counter("Next-header distribution:", next_header_counts)
    print_counter("IPv6 sources:", source_counts)
    print_counter("IPv6 destinations:", destination_counts)
    print_counter(
        "Ethernet MAC relationships:",
        Counter(
            {f"{source} -> {destination}": count for (source, destination), count in mac_pairs.items()}
        ),
    )


if __name__ == "__main__":
    main()
