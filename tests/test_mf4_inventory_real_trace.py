from pathlib import Path

from asammdf import MDF


MF4_FILE = Path(r"data\MF4\VW31666_0173_20260508_140000h_Trace.MF4")
KEYWORDS = (
    "vin",
    "charge",
    "charging",
    "lade",
    "battery",
    "batt",
    "soc",
    "current",
    "strom",
    "voltage",
    "spannung",
    "pilot",
    "cp",
    "pp",
    "connector",
    "stecker",
    "contactor",
    "schuetz",
    "interlock",
    "temperature",
    "temperatur",
    "hv",
    "can",
)


def test_mf4_inventory_real_trace() -> None:
    assert MF4_FILE.exists(), f"MF4 file not found: {MF4_FILE}"

    with MDF(MF4_FILE) as measurement:
        groups = measurement.groups
        channel_db = measurement.channels_db
        channel_names = sorted(str(name) for name in channel_db)
        start_time = measurement.start_time
        version = measurement.version

        group_channel_counts = []
        candidate_channels = []
        maximum_timestamp = None

        for group_index, group in enumerate(groups):
            channels = group.channels
            group_channel_counts.append(len(channels))
            channel_group = group.channel_group
            cycles = getattr(channel_group, "cycles_nr", None)
            print(
                f"Group {group_index}: channels={len(channels)}, "
                f"cycles={cycles}"
            )

        for name in channel_names:
            lowered = name.lower()
            if any(keyword in lowered for keyword in KEYWORDS):
                candidate_channels.append(name)

        for name in channel_names:
            try:
                signal = measurement.get(name)
            except Exception:
                continue

            if len(signal.timestamps):
                last_timestamp = float(signal.timestamps[-1])
                if maximum_timestamp is None or last_timestamp > maximum_timestamp:
                    maximum_timestamp = last_timestamp

        print("\nReal MF4 inventory")
        print(f"File: {MF4_FILE}")
        print(f"MDF version: {version}")
        print(f"Start time: {start_time.isoformat()}")
        print(f"File size: {MF4_FILE.stat().st_size:,} bytes")
        print(f"Channel groups: {len(groups)}")
        print(f"Unique channel names: {len(channel_names)}")
        print(f"Maximum observed timestamp: {maximum_timestamp}")
        print("Group channel counts: " + ", ".join(str(value) for value in group_channel_counts))

        print("\nAll channel names:")
        for name in channel_names:
            occurrences = channel_db[name]
            print(f"  {name} | occurrences={len(occurrences)}")

        print("\nCandidate vehicle/charging channels:")
        if candidate_channels:
            for name in candidate_channels:
                occurrences = channel_db[name]
                print(f"  {name} | occurrences={len(occurrences)}")
        else:
            print("  NONE")

        print("\nCandidate channel details:")
        for name in candidate_channels:
            try:
                signal = measurement.get(name)
            except Exception as exc:
                print(f"  {name} | read_error={type(exc).__name__}")
                continue

            sample_count = len(signal.samples)
            first_timestamp = float(signal.timestamps[0]) if sample_count else None
            last_timestamp = float(signal.timestamps[-1]) if sample_count else None
            print(
                f"  {name} | unit={signal.unit or ''} | samples={sample_count} | "
                f"first_ts={first_timestamp} | last_ts={last_timestamp}"
            )

        assert len(groups) > 0
        assert len(channel_names) > 0
