import argparse
from collections import Counter
from datetime import datetime
from pathlib import Path

from readers.pcap_reader import PcapReader
from services.iotecha_hpgp_decoder_service import IotechaHpgpDecoderService


DEFAULT_PCAP = Path(r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap")
SLAC_MATCH_CNF = "CM_SLAC_MATCH.CNF"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", nargs="?", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--preview", type=int, default=80)
    parser.add_argument("--mmtype", action="append")
    parser.add_argument("--end-packet", type=int)
    return parser.parse_args()


def normalize_mmtype(value):
    value = value.strip().upper()
    if not value.startswith("0X"):
        value = "0X" + value
    number = int(value, 16)
    if not 0 <= number <= 0xFFFF:
        raise ValueError(value)
    return f"0x{number:04X}"


def parse_timestamp(value):
    if not value:
        return None
    return datetime.fromisoformat(value)


def frame_payload(frame):
    data = frame.get("data", b"")
    if not isinstance(data, bytes) or len(data) < 17:
        return b""
    ethertype = int.from_bytes(data[12:14], "big")
    header_length = 18 if ethertype in {0x8100, 0x88A8} else 14
    return data[header_length:]


def find_last_slac_match_cnf(records):
    matches = []
    for record in records:
        packet_index = record.get("packet_index")
        if not isinstance(packet_index, int):
            continue
        for frame in record.get("embedded_frames", []):
            if frame.get("subtype") == SLAC_MATCH_CNF:
                matches.append(
                    {
                        "packet_number": packet_index + 1,
                        "timestamp": record.get("timestamp"),
                    }
                )
    if not matches:
        return None
    return max(matches, key=lambda item: item["packet_number"])


def collect_post_slac_frames(records, anchor, mmtypes, end_packet):
    frames = []
    anchor_time = parse_timestamp(anchor["timestamp"])

    for record in records:
        packet_index = record.get("packet_index")
        if not isinstance(packet_index, int):
            continue

        packet_number = packet_index + 1
        if packet_number <= anchor["packet_number"]:
            continue
        if end_packet is not None and packet_number > end_packet:
            continue

        timestamp = record.get("timestamp")
        event_time = parse_timestamp(timestamp)
        delta_ms = None
        if anchor_time is not None and event_time is not None:
            delta_ms = (event_time - anchor_time).total_seconds() * 1000.0

        for frame in record.get("embedded_frames", []):
            if frame.get("ethertype") != "0x88E1":
                continue

            mmtype = frame.get("mmtype")
            if not mmtype:
                continue
            if mmtypes is not None and mmtype not in mmtypes:
                continue

            frames.append(
                {
                    "packet_number": packet_number,
                    "timestamp": timestamp,
                    "delta_ms": delta_ms,
                    "record_class": record.get("record_class"),
                    "frame": frame,
                }
            )

    frames.sort(key=lambda item: item["packet_number"])
    return frames


def print_frame(item, preview_length):
    frame = item["frame"]
    payload = frame_payload(frame)
    delta = "-" if item["delta_ms"] is None else f"{item['delta_ms']:.3f} ms"

    print()
    print(
        f"packet={item['packet_number']} timestamp={item['timestamp']} "
        f"after_match={delta}"
    )
    print(
        f"  {frame['source_mac']} -> {frame['destination_mac']} "
        f"mmtype={frame['mmtype']} subtype={frame.get('subtype') or '-'}"
    )
    print(
        f"  payload_offset={frame['offset']} packet_offset={frame['packet_offset']} "
        f"captured_length={frame['captured_length']} "
        f"boundary={frame['boundary_source']}"
    )
    print(f"  homeplug_payload={payload[:preview_length].hex(' ')}")


def print_counter(title, counter):
    print()
    print(title)
    if not counter:
        print("  none")
        return
    for key, count in counter.most_common():
        print(f"  {str(key):<42} {count}")


def main():
    args = parse_args()

    if not args.pcap.exists():
        raise SystemExit(f"PCAP file not found: {args.pcap}")
    if args.limit < 0:
        raise SystemExit("--limit cannot be negative")
    if args.preview < 0:
        raise SystemExit("--preview cannot be negative")

    mmtypes = None
    if args.mmtype:
        try:
            mmtypes = {normalize_mmtype(value) for value in args.mmtype}
        except ValueError as exc:
            raise SystemExit(f"Invalid MMTYPE: {exc.args[0]}") from exc

    trace = PcapReader().read(args.pcap)
    service = IotechaHpgpDecoderService()
    records = service.decode_trace(trace)

    anchor = find_last_slac_match_cnf(records)
    if anchor is None:
        raise SystemExit("No recovered CM_SLAC_MATCH.CNF found")

    frames = collect_post_slac_frames(
        records=records,
        anchor=anchor,
        mmtypes=mmtypes,
        end_packet=args.end_packet,
    )

    shown = frames[:args.limit] if args.limit else frames

    for item in shown:
        print_frame(item, args.preview)

    mmtype_counts = Counter(item["frame"]["mmtype"] for item in frames)
    subtype_counts = Counter(
        item["frame"].get("subtype") or item["frame"]["mmtype"]
        for item in frames
    )
    direction_counts = Counter(
        f"{item['frame']['source_mac']} -> {item['frame']['destination_mac']}"
        for item in frames
    )
    mmtype_direction_counts = Counter(
        (
            item["frame"]["mmtype"],
            item["frame"]["source_mac"],
            item["frame"]["destination_mac"],
        )
        for item in frames
    )

    first_by_mmtype = {}
    last_by_mmtype = {}
    for item in frames:
        mmtype = item["frame"]["mmtype"]
        first_by_mmtype.setdefault(mmtype, item)
        last_by_mmtype[mmtype] = item

    print()
    print("=" * 72)
    print("Post-SLAC recovered HomePlug inspection summary")
    print("=" * 72)
    print(f"PCAP                  : {args.pcap}")
    print(f"Decoded records       : {len(records)}")
    print(f"SLAC_MATCH.CNF packet : {anchor['packet_number']}")
    print(f"SLAC_MATCH.CNF time   : {anchor['timestamp']}")
    print(f"Post-SLAC frames      : {len(frames)}")
    print(f"Displayed frames      : {len(shown)}")

    print_counter("MMTYPE distribution:", mmtype_counts)
    print_counter("Subtype distribution:", subtype_counts)
    print_counter("MAC directions:", direction_counts)

    print()
    print("MMTYPE directions:")
    if mmtype_direction_counts:
        for (mmtype, source, destination), count in mmtype_direction_counts.most_common():
            print(f"  {mmtype}  {source} -> {destination}  {count}")
    else:
        print("  none")

    print()
    print("MMTYPE timing relative to SLAC_MATCH.CNF:")
    if first_by_mmtype:
        for mmtype in sorted(first_by_mmtype):
            first = first_by_mmtype[mmtype]
            last = last_by_mmtype[mmtype]
            first_delta = "-" if first["delta_ms"] is None else f"{first['delta_ms']:.3f} ms"
            last_delta = "-" if last["delta_ms"] is None else f"{last['delta_ms']:.3f} ms"
            print(
                f"  {mmtype} first_packet={first['packet_number']} first={first_delta} "
                f"last_packet={last['packet_number']} last={last_delta}"
            )
    else:
        print("  none")


if __name__ == "__main__":
    main()
