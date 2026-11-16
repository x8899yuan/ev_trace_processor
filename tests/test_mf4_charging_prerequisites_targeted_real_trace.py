from collections import Counter
from pathlib import Path

import numpy as np
from asammdf import MDF


MF4_FILE = Path(r"data\MF4\VW31666_0173_20260508_140000h_Trace.MF4")
TARGET_TERMS = (
    "ladevorgang",
    "stecker",
    "ladebereit",
    "ladeart",
    "ladestrom",
    "ladespann",
    "cp_",
    "pilot",
    "riso",
    "iststrom_hv",
    "schuetz",
    "interlock",
)
MAX_VALUES = 16


def _text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, np.generic):
        value = value.item()
    return str(value)


def _transitions(values) -> int:
    if len(values) < 2:
        return 0
    return sum(
        _text(values[index]) != _text(values[index - 1])
        for index in range(1, len(values))
    )


def _distribution(samples) -> str:
    array = np.asarray(samples)
    if array.size == 0:
        return "NO_SAMPLES"

    if array.dtype.kind in "biufc":
        finite = array[np.isfinite(array)] if array.dtype.kind in "fc" else array
        if finite.size == 0:
            return "NO_FINITE_SAMPLES"
        unique = np.unique(finite)
        if unique.size <= MAX_VALUES:
            counts = Counter(_text(value) for value in finite.tolist())
            return ", ".join(f"{value}={count}" for value, count in counts.most_common())
        return (
            f"min={float(np.min(finite)):.6g}, "
            f"max={float(np.max(finite)):.6g}, "
            f"mean={float(np.mean(finite)):.6g}, unique={unique.size}"
        )

    counts = Counter(_text(value) for value in array.tolist())
    items = counts.most_common(MAX_VALUES)
    result = ", ".join(f"{value}={count}" for value, count in items)
    if len(counts) > MAX_VALUES:
        result += f", ... unique={len(counts)}"
    return result


def test_mf4_charging_prerequisites_targeted_real_trace() -> None:
    assert MF4_FILE.exists(), f"MF4 file not found: {MF4_FILE}"

    with MDF(MF4_FILE) as measurement:
        targets = []

        for name, occurrences in measurement.channels_db.items():
            text = str(name)
            lowered = text.lower()
            if not any(term in lowered for term in TARGET_TERMS):
                continue
            for group_index, channel_index in occurrences:
                targets.append((text, group_index, channel_index))

        targets.sort(key=lambda item: (item[0].lower(), item[1], item[2]))

        print("\nTargeted MF4 charging-prerequisite scan")
        print(f"File: {MF4_FILE}")
        print(f"Target occurrences: {len(targets)}")

        readable = 0
        by_name = {}

        for name, group_index, channel_index in targets:
            try:
                signal = measurement.get(
                    name,
                    group=group_index,
                    index=channel_index,
                )
            except Exception as exc:
                print(
                    f"READ_ERROR | {name} | group={group_index} | "
                    f"index={channel_index} | {type(exc).__name__}: {exc}"
                )
                continue

            readable += 1
            samples = signal.samples
            count = len(samples)
            first_value = _text(samples[0]) if count else "NO_SAMPLES"
            last_value = _text(samples[-1]) if count else "NO_SAMPLES"
            first_ts = float(signal.timestamps[0]) if count else None
            last_ts = float(signal.timestamps[-1]) if count else None
            transitions = _transitions(samples)
            distribution = _distribution(samples)

            print("\n" + "-" * 80)
            print(f"Channel: {name}")
            print(f"Location: group={group_index}, index={channel_index}")
            print(f"Unit: {signal.unit or ''}")
            print(f"Samples: {count}")
            print(f"Time: {first_ts} -> {last_ts}")
            print(f"First value: {first_value}")
            print(f"Last value: {last_value}")
            print(f"Transitions: {transitions}")
            print(f"Distribution: {distribution}")

            by_name.setdefault(name, []).append(
                {
                    "group": group_index,
                    "index": channel_index,
                    "first": first_value,
                    "last": last_value,
                    "transitions": transitions,
                    "distribution": distribution,
                }
            )

        duplicate_names = {
            name: entries
            for name, entries in by_name.items()
            if len(entries) > 1
        }

        print("\nDuplicate targeted channel comparison:")
        if not duplicate_names:
            print("  NONE")
        else:
            for name, entries in sorted(duplicate_names.items()):
                signatures = {
                    (entry["first"], entry["last"], entry["distribution"])
                    for entry in entries
                }
                status = "AGREE" if len(signatures) == 1 else "DIFFER"
                locations = ", ".join(
                    f"({entry['group']},{entry['index']})" for entry in entries
                )
                print(f"  {name} | {status} | locations={locations}")

        assert targets, "No targeted MF4 charging-prerequisite channels were found"
        assert readable > 0, "No targeted MF4 charging-prerequisite channel could be read"
