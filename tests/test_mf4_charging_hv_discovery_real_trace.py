from collections import Counter
from pathlib import Path

import numpy as np
import pytest
from asammdf import MDF


MF4_DIR = Path("data") / "MF4"
KEYWORDS = (
    "lade", "charge", "charging", "stecker", "connector", "pilot", "cp_",
    "pp_", "strom", "current", "spannung", "voltage", "soc", "batt",
    "battery", "riso", "iso", "schuetz", "contactor", "interlock", "hvlm",
    "hvlx", "hv_", "_hv",
)
MAX_PRINTED_CHANNELS = 120
MAX_DISTRIBUTION_VALUES = 12


def _discover_mf4_file() -> Path:
    files = sorted(
        path for path in MF4_DIR.iterdir()
        if path.is_file() and path.suffix.lower() == ".mf4"
    ) if MF4_DIR.exists() else []
    if not files:
        pytest.skip(f"No MF4 real-trace fixture found under {MF4_DIR}")
    return files[0]


def _text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, np.generic):
        value = value.item()
    return str(value)


def _summarize(samples) -> str:
    array = np.asarray(samples)
    if array.size == 0:
        return "NO_SAMPLES"
    if array.dtype.kind in "biufc":
        finite = array[np.isfinite(array)] if array.dtype.kind in "fc" else array
        if finite.size == 0:
            return "NO_FINITE_SAMPLES"
        unique = np.unique(finite)
        if unique.size <= MAX_DISTRIBUTION_VALUES:
            counts = Counter(_text(value) for value in finite.tolist())
            return "values=" + ", ".join(f"{value}:{count}" for value, count in counts.most_common())
        return f"min={float(np.min(finite)):.6g}, max={float(np.max(finite)):.6g}, mean={float(np.mean(finite)):.6g}, unique={unique.size}"
    counts = Counter(_text(value) for value in array.tolist())
    parts = [f"{value}:{count}" for value, count in counts.most_common(MAX_DISTRIBUTION_VALUES)]
    suffix = "" if len(counts) <= MAX_DISTRIBUTION_VALUES else f", ... unique={len(counts)}"
    return "values=" + ", ".join(parts) + suffix


def test_mf4_charging_hv_discovery_real_trace() -> None:
    mf4_file = _discover_mf4_file()
    with MDF(mf4_file) as measurement:
        candidates = []
        for name, occurrences in measurement.channels_db.items():
            lowered = str(name).lower()
            if any(keyword in lowered for keyword in KEYWORDS):
                for group_index, channel_index in occurrences:
                    candidates.append((str(name), group_index, channel_index))
        candidates.sort(key=lambda item: (item[0].lower(), item[1], item[2]))
        print("\nFocused MF4 charging/HV discovery")
        print(f"File: {mf4_file}")
        print(f"Candidate occurrences: {len(candidates)}")
        printed = 0
        readable = 0
        for name, group_index, channel_index in candidates:
            if printed >= MAX_PRINTED_CHANNELS:
                break
            try:
                signal = measurement.get(name, group=group_index, index=channel_index)
            except Exception as exc:
                print(f"READ_ERROR | {name} | group={group_index} | index={channel_index} | {type(exc).__name__}: {exc}")
                printed += 1
                continue
            readable += 1
            printed += 1
            sample_count = len(signal.samples)
            first_ts = float(signal.timestamps[0]) if sample_count else None
            last_ts = float(signal.timestamps[-1]) if sample_count else None
            print("\n" + "-" * 80)
            print(f"Channel: {name}")
            print(f"Location: group={group_index}, index={channel_index}")
            print(f"Unit: {signal.unit or ''}")
            print(f"Samples: {sample_count}")
            print(f"Time: {first_ts} -> {last_ts}")
            print(f"Data: {_summarize(signal.samples)}")
        if len(candidates) > MAX_PRINTED_CHANNELS:
            print(f"\nOutput limited to first {MAX_PRINTED_CHANNELS} candidate occurrences out of {len(candidates)}.")
        assert candidates, "No charging/HV-related MF4 channels were found"
        assert readable > 0, "No charging/HV candidate channel could be read"
