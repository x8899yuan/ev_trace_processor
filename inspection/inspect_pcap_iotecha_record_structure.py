from collections import Counter, defaultdict
from pathlib import Path

from readers.pcap_reader import PcapReader


PCAP_FILE = Path(
    r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap"
)
HEADER_BYTES = 48
TRIPLET_WINDOW_SECONDS = 0.002
SAMPLE_TRIPLETS = 8


def hex_bytes(data: bytes) -> str:
    return " ".join(f"{value:02X}" for value in data)


def ascii_text(data: bytes) -> str:
    return "".join(chr(value) if 32 <= value <= 126 else "." for value in data)


def u16_le(data: bytes, offset: int) -> int | None:
    if offset + 2 > len(data):
        return None
    return int.from_bytes(data[offset:offset + 2], "little")


def u16_be(data: bytes, offset: int) -> int | None:
    if offset + 2 > len(data):
        return None
    return int.from_bytes(data[offset:offset + 2], "big")


def stable_positions(samples: list[bytes], limit: int) -> list[tuple[int, int]]:
    if not samples:
        return []

    max_offset = min(limit, min(len(sample) for sample in samples))
    result = []

    for offset in range(max_offset):
        values = {sample[offset] for sample in samples}
        if len(values) == 1:
            result.append((offset, next(iter(values))))

    return result


def changing_positions(samples: list[bytes], limit: int) -> list[int]:
    if not samples:
        return []

    max_offset = min(limit, min(len(sample) for sample in samples))
    result = []

    for offset in range(max_offset):
        if len({sample[offset] for sample in samples}) > 1:
            result.append(offset)

    return result


def printable_runs(data: bytes, minimum_length: int = 6) -> list[tuple[int, str]]:
    results = []
    start = None
    current = bytearray()

    for offset, value in enumerate(data):
        if 32 <= value <= 126:
            if start is None:
                start = offset
            current.append(value)
        else:
            if start is not None and len(current) >= minimum_length:
                results.append((start, current.decode("ascii", errors="ignore")))
            start = None
            current.clear()

    if start is not None and len(current) >= minimum_length:
        results.append((start, current.decode("ascii", errors="ignore")))

    return results


def main() -> None:
    trace = PcapReader().read(PCAP_FILE)
    records = []
    by_length = defaultdict(list)
    byte16_18 = Counter()
    bytes24_39 = Counter()
    identifiers = Counter()

    for index, event in enumerate(trace.events):
        payload = event.payload
        if payload.get("protocol") != "HOMEPLUG_AV":
            continue

        data = payload.get("ethernet_payload")
        if not isinstance(data, bytes):
            continue

        record = {
            "index": index,
            "timestamp": event.timestamp,
            "src_mac": payload.get("src_mac"),
            "dst_mac": payload.get("dst_mac"),
            "data": data,
            "length": len(data),
        }
        records.append(record)
        by_length[len(data)].append(record)

        if len(data) >= 19:
            byte16_18[data[16:19]] += 1

        if len(data) >= 40:
            bytes24_39[data[24:40]] += 1

        for offset, text in printable_runs(data):
            if text == "74180400401c" or "IoTecha" in text or "sniffer" in text:
                identifiers[(offset, text)] += 1

    print("File:", PCAP_FILE)
    print("HomePlug records:", len(records))
    print()

    print("Record class candidates from bytes 16..18")
    for value, count in byte16_18.most_common(20):
        print(f"  {hex_bytes(value)}: {count:,}")

    print()
    print("Length to bytes 16..18 mapping")
    for length, length_records in sorted(by_length.items(), key=lambda item: -len(item[1])):
        counts = Counter(
            record["data"][16:19]
            for record in length_records
            if len(record["data"]) >= 19
        )
        summary = ", ".join(
            f"{hex_bytes(value)}={count:,}"
            for value, count in counts.most_common(8)
        )
        print(f"  length={length:5d} | count={len(length_records):,} | {summary}")

    print()
    print("Stable and changing header positions by major length")
    for length, length_records in sorted(by_length.items(), key=lambda item: -len(item[1]))[:7]:
        samples = [record["data"] for record in length_records[:50]]
        stable = stable_positions(samples, HEADER_BYTES)
        changing = changing_positions(samples, HEADER_BYTES)
        print(f"  length={length:5d} | samples={len(samples)}")
        print(
            "    stable:",
            " ".join(f"{offset}:{value:02X}" for offset, value in stable),
        )
        print("    changing:", " ".join(str(offset) for offset in changing))

    print()
    print("Known analyzer identifiers")
    if identifiers:
        for (offset, text), count in identifiers.most_common():
            print(f"  offset={offset:4d} | count={count:,} | {text}")
    else:
        print("  None")

    print()
    print("Candidate repeating triplets 1305 -> 1303 -> 46")
    triplets = []

    for position in range(len(records) - 2):
        first = records[position]
        second = records[position + 1]
        third = records[position + 2]

        if (first["length"], second["length"], third["length"]) != (1305, 1303, 46):
            continue

        span = (third["timestamp"] - first["timestamp"]).total_seconds()
        if span <= TRIPLET_WINDOW_SECONDS:
            triplets.append((first, second, third, span))

    print("  count:", len(triplets))

    for number, (first, second, third, span) in enumerate(triplets[:SAMPLE_TRIPLETS], 1):
        print()
        print(f"  Triplet {number} | span={span:.6f}s")
        for label, record in (("A", first), ("B", second), ("C", third)):
            data = record["data"]
            print(
                f"    {label}: packet={record['index']} | length={record['length']} | "
                f"time={record['timestamp'].isoformat()}"
            )
            print(f"       prefix={hex_bytes(data[:HEADER_BYTES])}")
            if len(data) >= 40:
                print(
                    "       fields="
                    f"b12={data[12]:02X} "
                    f"b15={data[15]:02X} "
                    f"b16_18={hex_bytes(data[16:19])} "
                    f"u16le18={u16_le(data, 18)} "
                    f"u16be18={u16_be(data, 18)} "
                    f"b20_23={hex_bytes(data[20:24])} "
                    f"b24_39={hex_bytes(data[24:40])}"
                )

    print()
    print("Most common bytes 24..39 patterns")
    for value, count in bytes24_39.most_common(20):
        print(f"  {count:,} | {hex_bytes(value)}")

    print()
    print("Representative uncommon record classes")
    class_examples = {}
    for record in records:
        data = record["data"]
        if len(data) < 19:
            continue
        key = (len(data), data[16:19])
        if key not in class_examples:
            class_examples[key] = record

    for (length, class_bytes), record in list(class_examples.items())[:30]:
        data = record["data"]
        print(
            f"  packet={record['index']} | length={length} | "
            f"class={hex_bytes(class_bytes)}"
        )
        print(f"    HEX   {hex_bytes(data[:HEADER_BYTES])}")
        print(f"    ASCII {ascii_text(data[:HEADER_BYTES])}")


if __name__ == "__main__":
    main()
