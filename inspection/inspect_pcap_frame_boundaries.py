from collections import Counter, defaultdict
from pathlib import Path

from readers.pcap_reader import PcapReader
from services.iotecha_hpgp_decoder_service import IotechaHpgpDecoderService


PCAP_FILE = Path(
    r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap"
)
TARGET_CLASSES = {
    "measurement_primary",
    "measurement_secondary",
    "measurement_primary_variant",
    "measurement_block",
}
MAX_OFFSET = 160
SAMPLE_COUNT = 64
TOP_CANDIDATES = 30


def hex_bytes(data: bytes) -> str:
    return " ".join(f"{value:02X}" for value in data)


def entropy_like_score(samples: list[bytes], offset: int) -> float:
    values = []
    for sample in samples:
        if offset < len(sample):
            values.append(sample[offset])
    if not values:
        return 0.0
    return len(set(values)) / len(values)


def constant_prefix_length(left: bytes, right: bytes) -> int:
    limit = min(len(left), len(right))
    index = 0
    while index < limit and left[index] == right[index]:
        index += 1
    return index


def paired_difference_offsets(left: bytes, right: bytes, limit: int) -> list[int]:
    maximum = min(limit, len(left), len(right))
    return [offset for offset in range(maximum) if left[offset] != right[offset]]


def candidate_boundaries(samples: list[bytes]) -> list[tuple[int, float, float]]:
    results = []
    maximum = min(MAX_OFFSET, min(len(sample) for sample in samples))

    for offset in range(1, maximum - 1):
        before = entropy_like_score(samples, offset - 1)
        current = entropy_like_score(samples, offset)
        after = entropy_like_score(samples, offset + 1)
        jump = current - before
        persistence = (current + after) / 2.0
        score = jump + persistence * 0.25
        results.append((offset, score, current))

    return sorted(results, key=lambda item: item[1], reverse=True)


def repeated_markers(samples: list[bytes]) -> Counter:
    counts = Counter()
    for data in samples:
        maximum = min(MAX_OFFSET, len(data) - 3)
        for offset in range(maximum):
            token = data[offset:offset + 4]
            counts[(offset, token)] += 1
    return counts


def region_bytes(event) -> bytes | None:
    data = event.payload.get("ethernet_payload")
    if isinstance(data, bytes):
        return data
    return None


def main() -> None:
    trace = PcapReader().read(PCAP_FILE)
    decoder = IotechaHpgpDecoderService()
    decoded = decoder.decode_trace(trace)

    events_by_index = {index: event for index, event in enumerate(trace.events)}
    grouped = defaultdict(list)

    for record in decoded:
        if record["record_class"] not in TARGET_CLASSES:
            continue
        event = events_by_index[record["packet_index"]]
        data = region_bytes(event)
        if data is not None:
            grouped[(record["record_class"], len(data))].append(
                (record, data)
            )

    print("File:", PCAP_FILE)
    print("Decoded records:", len(decoded))
    print()

    print("Record groups")
    for (record_class, length), items in sorted(
        grouped.items(), key=lambda item: -len(item[1])
    ):
        print(f"  {record_class} | length={length} | count={len(items):,}")

    print()
    print("Candidate boundary ranking")
    for (record_class, length), items in sorted(
        grouped.items(), key=lambda item: -len(item[1])
    ):
        selected = [data for _, data in items[:SAMPLE_COUNT]]
        if len(selected) < 2:
            continue
        print()
        print(f"  {record_class} | length={length} | samples={len(selected)}")
        for offset, score, variability in candidate_boundaries(selected)[:12]:
            start = max(0, offset - 8)
            end = min(len(selected[0]), offset + 16)
            print(
                f"    offset={offset:3d} | score={score:.4f} | "
                f"variability={variability:.4f} | "
                f"sample={hex_bytes(selected[0][start:end])}"
            )

    print()
    print("Highly repeated four-byte markers by group")
    for (record_class, length), items in sorted(
        grouped.items(), key=lambda item: -len(item[1])
    ):
        selected = [data for _, data in items[:SAMPLE_COUNT]]
        markers = repeated_markers(selected)
        threshold = max(2, len(selected) * 3 // 4)
        stable = [
            (offset, token, count)
            for (offset, token), count in markers.items()
            if count >= threshold
        ]
        stable.sort(key=lambda item: (item[0], -item[2]))
        print()
        print(f"  {record_class} | length={length}")
        for offset, token, count in stable[:TOP_CANDIDATES]:
            print(
                f"    offset={offset:3d} | count={count:3d}/{len(selected)} | "
                f"{hex_bytes(token)}"
            )

    print()
    print("Adjacent-record structural correlation")
    correlations = Counter()
    examples = defaultdict(list)

    for left_record, right_record in zip(decoded, decoded[1:]):
        if left_record["record_class"] not in TARGET_CLASSES:
            continue
        if right_record["record_class"] not in TARGET_CLASSES:
            continue

        left_event = events_by_index[left_record["packet_index"]]
        right_event = events_by_index[right_record["packet_index"]]
        delta = (right_event.timestamp - left_event.timestamp).total_seconds()

        if delta > 0.002:
            continue

        left = region_bytes(left_event)
        right = region_bytes(right_event)
        if left is None or right is None:
            continue

        pair = (
            left_record["record_class"],
            len(left),
            right_record["record_class"],
            len(right),
        )
        prefix = constant_prefix_length(left, right)
        correlations[(pair, prefix)] += 1
        if len(examples[(pair, prefix)]) < 3:
            examples[(pair, prefix)].append(
                (
                    left_record["packet_index"],
                    right_record["packet_index"],
                    paired_difference_offsets(left, right, 80),
                )
            )

    for (pair, prefix), count in correlations.most_common(25):
        left_class, left_length, right_class, right_length = pair
        print(
            f"  {left_class}/{left_length} -> {right_class}/{right_length} | "
            f"common_prefix={prefix} | count={count:,}"
        )
        for left_index, right_index, differences in examples[(pair, prefix)]:
            print(
                f"    packets={left_index}->{right_index} | "
                f"different_offsets_under_80={differences}"
            )

    print()
    print("Known nested-subrecord boundaries")
    nested = Counter()
    for record in decoded:
        for region in record["regions"]:
            if region["type"] != "primary_record":
                nested[(
                    record["record_class"],
                    record["payload_length"],
                    region["type"],
                    region["offset"],
                )] += 1

    if nested:
        for key, count in nested.most_common():
            record_class, length, region_type, offset = key
            print(
                f"  {record_class} | length={length} | {region_type} | "
                f"offset={offset} | count={count:,}"
            )
    else:
        print("  None")

    print()
    print("Interpretation")
    print("  This tool ranks structural boundaries only.")
    print("  It does not label any recovered region as SLAC, IPv6, V2GTP, or certificate data.")
    print("  Repeated offsets across many records are stronger evidence than isolated byte signatures.")


if __name__ == "__main__":
    main()
