from collections import Counter, defaultdict
from pathlib import Path

from readers.pcap_reader import PcapReader


PCAP_FILE = Path(
    r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap"
)
PREFIX_BYTES = 48
SAMPLES_PER_LENGTH = 3
SCAN_BYTES = 40


def hex_bytes(data: bytes) -> str:
    return " ".join(f"{value:02X}" for value in data)


def ascii_text(data: bytes) -> str:
    return "".join(chr(value) if 32 <= value <= 126 else "." for value in data)


def stable_positions(samples: list[bytes], limit: int) -> list[tuple[int, int]]:
    if not samples:
        return []

    result = []
    max_offset = min(limit, min(len(sample) for sample in samples))

    for offset in range(max_offset):
        values = {sample[offset] for sample in samples}
        if len(values) == 1:
            result.append((offset, next(iter(values))))

    return result


def candidate_mme_headers(data: bytes) -> list[tuple[int, int, int]]:
    results = []
    max_offset = min(SCAN_BYTES, max(0, len(data) - 2))

    for offset in range(max_offset):
        mmv = data[offset]
        if mmv > 2:
            continue

        mmtype = int.from_bytes(data[offset + 1:offset + 3], "little")
        if 0x6000 <= mmtype <= 0x60FF:
            results.append((offset, mmv, mmtype))

    return results


def main() -> None:
    trace = PcapReader().read(PCAP_FILE)

    length_counts = Counter()
    samples_by_length = defaultdict(list)
    header_candidates = Counter()
    candidate_examples = defaultdict(list)

    for index, event in enumerate(trace.events):
        payload = event.payload
        if payload.get("protocol") != "HOMEPLUG_AV":
            continue

        data = payload.get("ethernet_payload")
        if not isinstance(data, bytes):
            continue

        length_counts[len(data)] += 1

        if len(samples_by_length[len(data)]) < SAMPLES_PER_LENGTH:
            samples_by_length[len(data)].append(
                (
                    index,
                    event.timestamp.isoformat(),
                    payload.get("src_mac"),
                    payload.get("dst_mac"),
                    data,
                )
            )

        for offset, mmv, mmtype in candidate_mme_headers(data):
            key = (offset, mmv, mmtype)
            header_candidates[key] += 1
            if len(candidate_examples[key]) < 3:
                candidate_examples[key].append((index, data[:PREFIX_BYTES]))

    print("File:", PCAP_FILE)
    print("Packets:", trace.event_count)
    print()

    print("HomePlug payload lengths")
    for length, count in length_counts.most_common(30):
        print(f"  {length:5d} bytes: {count:,}")

    print()
    print("Representative payload prefixes by length")
    for length, count in length_counts.most_common(15):
        entries = samples_by_length[length]
        print()
        print(f"Length {length} bytes | count={count:,}")

        raw_samples = [entry[4] for entry in entries]
        stable = stable_positions(raw_samples, PREFIX_BYTES)
        print(
            "  Stable prefix positions:",
            " ".join(f"{offset}:{value:02X}" for offset, value in stable)
            if stable
            else "None",
        )

        for index, timestamp, src, dst, data in entries:
            prefix = data[:PREFIX_BYTES]
            print(f"  packet={index} | {timestamp} | {src} -> {dst}")
            print(f"    HEX   {hex_bytes(prefix)}")
            print(f"    ASCII {ascii_text(prefix)}")

    print()
    print("Candidate MME header triples")
    if not header_candidates:
        print("  None")
    else:
        for (offset, mmv, mmtype), count in header_candidates.most_common(40):
            print(
                f"  offset={offset:2d} | MMV=0x{mmv:02X} | "
                f"MMTYPE=0x{mmtype:04X} | count={count:,}"
            )

    print()
    print("Representative candidate MME prefixes")
    for key, count in header_candidates.most_common(15):
        offset, mmv, mmtype = key
        print()
        print(
            f"offset={offset} | MMV=0x{mmv:02X} | "
            f"MMTYPE=0x{mmtype:04X} | count={count:,}"
        )
        for index, prefix in candidate_examples[key]:
            marker = ["  "] * len(prefix)
            if offset < len(marker):
                marker[offset] = "^^"
            print(f"  packet={index}")
            print(f"    HEX {hex_bytes(prefix)}")
            print("    POS " + " ".join(marker))


if __name__ == "__main__":
    main()
