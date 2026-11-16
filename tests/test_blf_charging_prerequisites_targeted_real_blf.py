from collections import Counter, defaultdict
from pathlib import Path

from readers.blf_reader import BlfReader
from services.dbc_decoder_service import DbcDecoderService


BLF_FILE = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")
DBC_FILE = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")
TARGET_CAN_IDS = [0x0CF, 0x271, 0x272, 0x503, 0x5A2]
PREREQUISITE_TERMS = (
    "lade",
    "bereit",
    "freig",
    "erlaub",
    "stecker",
    "verriegel",
    "cp_",
    "pp_",
    "pilot",
    "schuetz",
    "schütz",
    "kontaktor",
    "isolation",
    "isolat",
    "hv_aktiv",
    "hv_status",
    "hv_zustand",
)


def test_blf_charging_prerequisites_targeted_real_blf() -> None:
    assert BLF_FILE.exists(), f"BLF file not found: {BLF_FILE}"
    assert DBC_FILE.exists(), f"DBC file not found: {DBC_FILE}"

    trace = BlfReader().read(BLF_FILE)
    decoder = DbcDecoderService()
    supported = {}
    counts = defaultdict(Counter)
    transitions = Counter()
    previous = {}
    first_seen = {}
    last_seen = {}
    decoded_frames = Counter()

    for can_id in TARGET_CAN_IDS:
        if decoder.message_exists(DBC_FILE, can_id):
            supported[can_id] = decoder.message_name(DBC_FILE, can_id)

    for event in trace.events:
        if event.source_type.upper() != "BLF" or event.event_name != "CAN_FRAME":
            continue

        can_id = event.payload.get("arbitration_id")
        if can_id not in supported:
            continue

        data_hex = event.payload.get("data")
        if not isinstance(data_hex, str):
            continue

        try:
            decoded = decoder.decode_message(DBC_FILE, can_id, bytes.fromhex(data_hex))
        except (KeyError, ValueError, TypeError):
            continue

        decoded_frames[can_id] += 1

        for signal, value in decoded.items():
            name = signal.lower()
            if not any(term in name for term in PREREQUISITE_TERMS):
                continue

            key = (can_id, signal)
            printable = str(value)
            counts[key][printable] += 1
            first_seen.setdefault(key, (event.timestamp, printable))
            last_seen[key] = (event.timestamp, printable)

            if key in previous and previous[key] != printable:
                transitions[key] += 1
            previous[key] = printable

    print("\nCharging prerequisite-focused BLF scan")
    print(f"BLF: {BLF_FILE}")
    print(f"DBC: {DBC_FILE}")
    print("Supported target messages:")
    for can_id in sorted(supported):
        print(f"  0x{can_id:X}: {supported[can_id]} | decoded frames: {decoded_frames[can_id]}")

    if not counts:
        print("No prerequisite-related signals matched the focused naming terms.")
        return

    print("\nPrerequisite-related decoded signals:")
    for can_id, signal in sorted(counts):
        key = (can_id, signal)
        first_timestamp, first_value = first_seen[key]
        last_timestamp, last_value = last_seen[key]
        print("\n" + "-" * 80)
        print(f"CAN ID: 0x{can_id:X}")
        print(f"Message: {supported[can_id]}")
        print(f"Signal: {signal}")
        print(f"Observations: {sum(counts[key].values())}")
        print(f"Transitions: {transitions[key]}")
        print(f"First: {first_timestamp.isoformat()} | {first_value}")
        print(f"Last:  {last_timestamp.isoformat()} | {last_value}")
        print("Value distribution:")
        for value, count in counts[key].most_common():
            print(f"  {value}: {count}")
