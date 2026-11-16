from collections import Counter
from pathlib import Path

from readers.pcap_reader import PcapReader


PCAP_FILE = Path(
    r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap"
)
TARGET_LENGTHS = {184, 440, 594}
MAX_SAMPLES = 5


def hex_bytes(data: bytes) -> str:
    return " ".join(f"{value:02X}" for value in data)


def printable_runs(data: bytes, minimum_length: int = 4) -> list[tuple[int, str]]:
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


def longest_common_suffix(left: bytes, right: bytes) -> int:
    count = 0
    maximum = min(len(left), len(right))

    while count < maximum and left[-1 - count] == right[-1 - count]:
        count += 1

    return count


def find_subsequence(data: bytes, pattern: bytes) -> list[int]:
    results = []
    start = 0

    while True:
        offset = data.find(pattern, start)
        if offset < 0:
            break
        results.append(offset)
        start = offset + 1

    return results


def length_prefixed_strings(data: bytes) -> list[tuple[int, int, str]]:
    results = []

    for offset in range(len(data)):
        length = data[offset]
        if length < 4 or length > 80:
            continue

        end = offset + 1 + length
        if end > len(data):
            continue

        value = data[offset + 1:end]
        if all(32 <= item <= 126 for item in value):
            results.append((offset, length, value.decode("ascii")))

    return results


def main() -> None:
    trace = PcapReader().read(PCAP_FILE)
    records: dict[int, list[dict]] = {length: [] for length in TARGET_LENGTHS}

    for index, event in enumerate(trace.events):
        payload = event.payload
        if payload.get("protocol") != "HOMEPLUG_AV":
            continue

        data = payload.get("ethernet_payload")
        if not isinstance(data, bytes) or len(data) not in TARGET_LENGTHS:
            continue

        records[len(data)].append(
            {
                "index": index,
                "timestamp": event.timestamp,
                "data": data,
            }
        )

    print("File:", PCAP_FILE)
    print()

    for length in sorted(TARGET_LENGTHS):
        items = records[length]
        print(f"Length {length}: {len(items):,} records")

        class_counts = Counter(
            item["data"][16:19]
            for item in items
            if len(item["data"]) >= 19
        )
        for value, count in class_counts.most_common():
            print(f"  class {hex_bytes(value)}: {count:,}")
        print()

    metadata_strings = (
        b"74180400401c",
        b"git-8b07423be2e0 sniffer-n",
        b"IoTecha HPGP Analyzer",
    )

    print("Metadata string offsets")
    for length in sorted(TARGET_LENGTHS):
        offsets = {pattern: Counter() for pattern in metadata_strings}

        for item in records[length]:
            data = item["data"]
            for pattern in metadata_strings:
                for offset in find_subsequence(data, pattern):
                    offsets[pattern][offset] += 1

        print(f"  Length {length}")
        for pattern in metadata_strings:
            text = pattern.decode("ascii")
            if offsets[pattern]:
                summary = ", ".join(
                    f"offset {offset}={count:,}"
                    for offset, count in offsets[pattern].most_common()
                )
                print(f"    {text}: {summary}")
            else:
                print(f"    {text}: not present")

    print()
    print("Length-prefixed printable fields")
    for length in sorted(TARGET_LENGTHS):
        counts = Counter()

        for item in records[length]:
            for offset, field_length, text in length_prefixed_strings(item["data"]):
                if len(text) >= 6:
                    counts[(offset, field_length, text)] += 1

        print(f"  Length {length}")
        if not counts:
            print("    None")
            continue

        for (offset, field_length, text), count in counts.most_common(30):
            print(
                f"    offset={offset:4d} | len={field_length:2d} | "
                f"count={count:,} | {text}"
            )

    print()
    print("440 vs 594 structural comparison")
    records_440 = records[440]
    records_594 = records[594]

    for number, item_594 in enumerate(records_594[:MAX_SAMPLES], 1):
        data_594 = item_594["data"]
        best = None

        for item_440 in records_440:
            data_440 = item_440["data"]
            prefix_match = 0
            maximum = min(len(data_440), len(data_594))

            while prefix_match < maximum and data_440[prefix_match] == data_594[prefix_match]:
                prefix_match += 1

            suffix_match = longest_common_suffix(data_440, data_594)
            score = prefix_match + suffix_match

            if best is None or score > best[0]:
                best = (score, prefix_match, suffix_match, item_440)

        print()
        print(
            f"  594 sample {number}: packet={item_594['index']} | "
            f"time={item_594['timestamp'].isoformat()}"
        )

        if best is None:
            print("    No 440-byte comparison available")
            continue

        _, prefix_match, suffix_match, item_440 = best
        print(
            f"    closest 440 packet={item_440['index']} | "
            f"prefix_match={prefix_match} | suffix_match={suffix_match}"
        )
        print(f"    594 first 64: {hex_bytes(data_594[:64])}")
        print(f"    440 first 64: {hex_bytes(item_440['data'][:64])}")
        print(f"    594 last 192: {hex_bytes(data_594[-192:])}")

    print()
    print("184-byte analyzer metadata samples")
    for item in records[184][:MAX_SAMPLES]:
        data = item["data"]
        print()
        print(
            f"  packet={item['index']} | "
            f"time={item['timestamp'].isoformat()}"
        )
        print(f"    HEX 0..95:   {hex_bytes(data[:96])}")
        print(f"    HEX 96..183: {hex_bytes(data[96:])}")
        print("    Printable fields:")
        for offset, text in printable_runs(data, 4):
            print(f"      offset={offset:3d} | {text}")
        print("    Length-prefixed fields:")
        for offset, field_length, text in length_prefixed_strings(data):
            print(
                f"      offset={offset:3d} | len={field_length:2d} | {text}"
            )

    print()
    print("594-byte metadata-tail samples")
    for item in records[594][:MAX_SAMPLES]:
        data = item["data"]
        print()
        print(
            f"  packet={item['index']} | "
            f"time={item['timestamp'].isoformat()}"
        )
        print(f"    HEX 400..593: {hex_bytes(data[400:])}")
        print("    Printable fields after offset 400:")
        for offset, text in printable_runs(data[400:], 4):
            print(f"      offset={offset + 400:3d} | {text}")
        print("    Length-prefixed fields after offset 400:")
        for offset, field_length, text in length_prefixed_strings(data[400:]):
            print(
                f"      offset={offset + 400:3d} | len={field_length:2d} | {text}"
            )


if __name__ == "__main__":
    main()
