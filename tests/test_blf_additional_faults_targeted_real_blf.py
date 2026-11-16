from collections import Counter, defaultdict
from pathlib import Path

from readers.blf_reader import BlfReader
from services.dbc_decoder_service import DbcDecoderService


BLF_FILE = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")
DBC_FILE = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")
TARGET_CAN_IDS = [0x0CF, 0x0F7, 0x153, 0x271, 0x3BE, 0x503, 0x530, 0x5A2, 0x5CD]
FAULT_TERMS = (
    "fehler",
    "fault",
    "error",
    "warn",
    "stoer",
    "stör",
    "abschalt",
    "shutdown",
    "crash",
    "interlock",
    "notaus",
    "emergency",
)


def test_blf_additional_faults_targeted_real_blf() -> None:
    assert BLF_FILE.exists(), f"BLF file not found: {BLF_FILE}"
    assert DBC_FILE.exists(), f"DBC file not found: {DBC_FILE}"

    trace = BlfReader().read(BLF_FILE)
    decoder = DbcDecoderService()
    message_cache = {}
    signal_counts = defaultdict(Counter)
    occurrences = Counter()
    first_seen = {}
    last_seen = {}
    transitions = Counter()
    previous_values = {}
    supported_ids = set()

    for can_id in TARGET_CAN_IDS:
        if decoder.message_exists(DBC_FILE, can_id):
            supported_ids.add(can_id)
            message_cache[can_id] = decoder.message_name(DBC_FILE, can_id)

    for event in trace.events:
        if event.source_type.upper() != "BLF" or event.event_name != "CAN_FRAME":
            continue

        can_id = event.payload.get("arbitration_id")
        if can_id not in supported_ids:
            continue

        data_hex = event.payload.get("data")
        if not isinstance(data_hex, str):
            continue

        try:
            decoded = decoder.decode_message(DBC_FILE, can_id, bytes.fromhex(data_hex))
        except (KeyError, ValueError, TypeError):
            continue

        for signal, value in decoded.items():
            if not any(term in signal.lower() for term in FAULT_TERMS):
                continue

            key = (can_id, signal)
            printable = str(value)
            signal_counts[key][printable] += 1
            occurrences[key] += 1
            first_seen.setdefault(key, (event.timestamp, printable))
            last_seen[key] = (event.timestamp, printable)

            if key in previous_values and previous_values[key] != printable:
                transitions[key] += 1
            previous_values[key] = printable

    print("\nTargeted BLF additional-fault scan")
    print(f"BLF: {BLF_FILE}")
    print(f"DBC: {DBC_FILE}")
    print("Supported target CAN IDs:", ", ".join(f"0x{x:X}" for x in sorted(supported_ids)) or "NONE")

    if not signal_counts:
        print("No fault-indicative signal names were decoded on the targeted CAN IDs.")
        return

    for can_id, signal in sorted(signal_counts):
        key = (can_id, signal)
        message_name = message_cache.get(can_id, "UNKNOWN")
        first_timestamp, first_value = first_seen[key]
        last_timestamp, last_value = last_seen[key]
        print("\n" + "-" * 80)
        print(f"CAN ID: 0x{can_id:X}")
        print(f"Message: {message_name}")
        print(f"Signal: {signal}")
        print(f"Observations: {occurrences[key]}")
        print(f"Transitions: {transitions[key]}")
        print(f"First: {first_timestamp.isoformat()} | {first_value}")
        print(f"Last:  {last_timestamp.isoformat()} | {last_value}")
        print("Value distribution:")
        for value, count in signal_counts[key].most_common():
            print(f"  {value}: {count}")
