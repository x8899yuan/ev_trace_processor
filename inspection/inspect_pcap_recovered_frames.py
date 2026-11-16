import argparse
from collections import Counter
from pathlib import Path

from readers.pcap_reader import PcapReader
from services.iotecha_hpgp_decoder_service import IotechaHpgpDecoderService


DEFAULT_PCAP = Path(r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap")
DEFAULT_MMTYPES = {
    "0x6002",
    "0x6006",
    "0x6064",
    "0x6065",
    "0x606A",
    "0x606E",
    "0x606F",
    "0x6076",
    "0x607C",
    "0x607D",
}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", nargs="?", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--packet", type=int)
    parser.add_argument("--mmtype", action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--preview", type=int, default=80)
    parser.add_argument("--limit", type=int, default=0)
    return parser.parse_args()


def normalize_mmtype(value):
    value = value.strip().upper()
    if not value.startswith("0X"):
        value = "0X" + value
    number = int(value, 16)
    if not 0 <= number <= 0xFFFF:
        raise ValueError(value)
    return f"0x{number:04X}"


def selected_mmtypes(args):
    if args.all:
        return None
    if not args.mmtype:
        return DEFAULT_MMTYPES
    return {normalize_mmtype(value) for value in args.mmtype}


def frame_payload(frame):
    data = frame["data"]
    if len(data) < 17:
        return b""
    ethertype = int.from_bytes(data[12:14], "big")
    header_length = 18 if ethertype in {0x8100, 0x88A8} else 14
    return data[header_length:]


def collect_frames(records, mmtypes, packet_filter):
    frames = []
    for record in records:
        packet_index = record.get("packet_index")
        packet_number = packet_index + 1 if isinstance(packet_index, int) else None
        if packet_filter is not None and packet_number != packet_filter:
            continue
        for frame in record.get("embedded_frames", []):
            if mmtypes is not None and frame.get("mmtype") not in mmtypes:
                continue
            frames.append({
                "packet_number": packet_number,
                "packet_index": packet_index,
                "timestamp": record.get("timestamp"),
                "record_class": record.get("record_class"),
                "frame": frame,
            })
    frames.sort(key=lambda item: (item["packet_index"] if item["packet_index"] is not None else -1))
    return frames


def print_frame(item, position, frames, preview_length):
    frame = item["frame"]
    payload = frame_payload(frame)
    previous_subtype = None
    next_subtype = None
    if position > 0:
        previous = frames[position - 1]["frame"]
        previous_subtype = previous.get("subtype") or previous.get("mmtype")
    if position + 1 < len(frames):
        following = frames[position + 1]["frame"]
        next_subtype = following.get("subtype") or following.get("mmtype")
    print()
    print(
        f"packet={item['packet_number']} "
        f"timestamp={item['timestamp']} "
        f"payload_offset={frame['offset']} "
        f"packet_offset={frame['packet_offset']}"
    )
    print(
        f"  {frame['source_mac']} -> {frame['destination_mac']} "
        f"protocol={frame['protocol']} mmtype={frame['mmtype']} "
        f"subtype={frame.get('subtype') or '-'}"
    )
    print(
        f"  record_class={item['record_class']} "
        f"boundary={frame['boundary_source']} "
        f"captured_length={frame['captured_length']}"
    )
    print(
        f"  previous={previous_subtype or '-'} "
        f"next={next_subtype or '-'}"
    )
    print(f"  homeplug_payload={payload[:preview_length].hex(' ')}")


def main():
    args = parse_args()
    if not args.pcap.exists():
        raise SystemExit(f"PCAP file not found: {args.pcap}")
    if args.preview < 0:
        raise SystemExit("--preview cannot be negative")
    if args.limit < 0:
        raise SystemExit("--limit cannot be negative")
    try:
        mmtypes = selected_mmtypes(args)
    except ValueError as exc:
        raise SystemExit(f"Invalid MMTYPE: {exc.args[0]}") from exc

    trace = PcapReader().read(args.pcap)
    service = IotechaHpgpDecoderService()
    records = service.decode_trace(trace)
    frames = collect_frames(records, mmtypes, args.packet)
    shown = frames[:args.limit] if args.limit else frames

    for position, item in enumerate(shown):
        print_frame(item, position, shown, args.preview)

    protocol_counts = Counter(item["frame"]["protocol"] for item in shown)
    mmtype_counts = Counter(item["frame"]["mmtype"] for item in shown)
    mac_pairs = Counter(
        (item["frame"]["source_mac"], item["frame"]["destination_mac"])
        for item in shown
    )

    print()
    print("=" * 72)
    print("Recovered embedded frame inspection summary")
    print("=" * 72)
    print(f"PCAP             : {args.pcap}")
    print(f"Decoded records  : {len(records)}")
    print(f"Matching frames  : {len(frames)}")
    print(f"Displayed frames : {len(shown)}")
    print()
    print("Protocols:")
    if protocol_counts:
        for protocol, count in protocol_counts.most_common():
            print(f"  {protocol:<12} {count}")
    else:
        print("  none")
    print()
    print("MMTYPEs:")
    if mmtype_counts:
        for mmtype, count in mmtype_counts.most_common():
            print(f"  {mmtype:<12} {count}")
    else:
        print("  none")
    print()
    print("MAC relationships:")
    if mac_pairs:
        for (source, destination), count in mac_pairs.most_common():
            print(f"  {source} -> {destination}  {count}")
    else:
        print("  none")


if __name__ == "__main__":
    main()
