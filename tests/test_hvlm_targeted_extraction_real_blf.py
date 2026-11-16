from pathlib import Path

from readers.blf_reader import BlfReader
from services.dbc_decoder_service import DbcDecoderService


BLF_FILE = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")
DBC_FILE = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")
TARGET_SIGNALS = {
    "HVLM_CDO_LadeerlaubnisLm",
    "HVLM_CDO_LadebereitFzg",
    "HVLM_CJ_LadebereitschaftFzg",
    "HVLM_CDO_Status_Fahrzeug",
    "HVLM_Ladevorgang_Anf",
    "HVLM_ZustandLadeablauf",
}


def test_hvlm_targeted_extraction_real_blf() -> None:
    assert BLF_FILE.exists(), f"BLF file not found: {BLF_FILE}"
    assert DBC_FILE.exists(), f"DBC file not found: {DBC_FILE}"

    decoder = DbcDecoderService()
    target_ids = set()

    for arbitration_id in range(0x800):
        try:
            if not decoder.message_exists(DBC_FILE, arbitration_id):
                continue
            decoded = decoder.decode_can_message(
                dbc_file=DBC_FILE,
                timestamp=0.0,
                channel=0,
                arbitration_id=arbitration_id,
                data=bytes(64),
            )
        except Exception:
            continue

        if TARGET_SIGNALS.intersection(decoded.signals):
            target_ids.add(arbitration_id)

    assert target_ids, "No CAN IDs containing target HVLM signals were found in the DBC"

    reader = BlfReader()
    samples = {signal: [] for signal in TARGET_SIGNALS}
    matched_frames = 0

    for event in reader.read_events(BLF_FILE):
        arbitration_id = event.payload.get("arbitration_id")
        data_hex = event.payload.get("data")

        if arbitration_id not in target_ids or not data_hex:
            continue

        try:
            decoded = decoder.decode_can_message(
                dbc_file=DBC_FILE,
                timestamp=event.timestamp.timestamp(),
                channel=event.payload.get("channel", 0),
                arbitration_id=arbitration_id,
                data=bytes.fromhex(data_hex),
            )
        except Exception:
            continue

        matched_frames += 1

        for signal_name in TARGET_SIGNALS:
            if signal_name not in decoded.signals:
                continue
            samples[signal_name].append(
                {
                    "timestamp": decoded.timestamp,
                    "value": decoded.signals[signal_name],
                    "arbitration_id": arbitration_id,
                    "channel": event.payload.get("channel", 0),
                }
            )

    populated = {name: values for name, values in samples.items() if values}

    print()
    print(f"Target CAN IDs: {[hex(value) for value in sorted(target_ids)]}")
    print(f"Matched target frames: {matched_frames}")

    for signal_name in sorted(TARGET_SIGNALS):
        signal_samples = samples[signal_name]
        print(f"{signal_name}: {len(signal_samples)} samples")
        if signal_samples:
            first = signal_samples[0]
            last = signal_samples[-1]
            print(
                f"  first={first['timestamp']:.6f} value={first['value']} "
                f"can_id={hex(first['arbitration_id'])} channel={first['channel']}"
            )
            print(
                f"  last={last['timestamp']:.6f} value={last['value']} "
                f"can_id={hex(last['arbitration_id'])} channel={last['channel']}"
            )

    assert matched_frames > 0
    assert populated, "Target HVLM CAN frames were found but no target signals decoded"
