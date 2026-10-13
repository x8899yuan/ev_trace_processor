from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_event_detection_service import (
    ChargingEventDetectionService,
)
from services.charging_timeline_service import (
    ChargingTimelineService,
)
from services.dbc_decoder_service import DbcDecoderService
from services.signal_extraction_service import (
    SignalExtractionService,
)


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)

DBC_FILE = Path(
    r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)

TEST_SIGNALS = [
    "HVLM_CDO_LadeerlaubnisLm",
    "HVLM_CDO_LadebereitFzg",
    "HVLM_CJ_LadebereitschaftFzg",
    "HVLM_CDO_Status_Fahrzeug",
    "HVLM_Ladevorgang_Anf",
    "HVLM_ZustandLadeablauf",
]


def test_charging_event_detection_real_blf() -> None:
    assert BLF_FILE.exists(), f"BLF file not found: {BLF_FILE}"
    assert DBC_FILE.exists(), f"DBC file not found: {DBC_FILE}"

    reader = BlfReader()
    events = reader.read_events(
        BLF_FILE,
        max_events=10000,
    )

    decoder = DbcDecoderService()
    decoded_messages = []

    for event in events:
        arbitration_id = event.payload.get("arbitration_id")
        data_hex = event.payload.get("data")

        if arbitration_id is None or not data_hex:
            continue

        try:
            if not decoder.message_exists(
                DBC_FILE,
                arbitration_id,
            ):
                continue

            decoded_message = decoder.decode_can_message(
                dbc_file=DBC_FILE,
                timestamp=event.timestamp,
                channel=event.payload.get("channel", 0),
                arbitration_id=arbitration_id,
                data=bytes.fromhex(data_hex),
            )

            decoded_messages.append(decoded_message)
        except Exception:
            continue

    assert decoded_messages

    extractor = SignalExtractionService()
    signal_samples = {}

    for signal_name in TEST_SIGNALS:
        samples = extractor.extract(
            decoded_messages,
            signal_name,
        )

        if samples:
            signal_samples[signal_name] = samples

    timeline_service = ChargingTimelineService()
    timeline = timeline_service.build_timeline(signal_samples)

    event_detection_service = ChargingEventDetectionService()
    detected_events = event_detection_service.detect_events(timeline)

    print()
    print(f"Decoded Messages: {len(decoded_messages)}")
    print()
    print("Signal Sample Counts")
    print("=" * 80)

    for signal_name, samples in signal_samples.items():
        print(f"{signal_name}: {len(samples)}")

    print()
    print("Detected Charging Events")
    print("=" * 80)

    for detected_event in detected_events:
        print(
            f"{detected_event['timestamp']} | "
            f"{detected_event['signal']} | "
            f"{detected_event['value']} | "
            f"{detected_event['description']}"
        )

    print()
    print(f"Signals Found: {len(signal_samples)}")
    print(f"Timeline Events: {len(timeline)}")
    print(f"Detected Events: {len(detected_events)}")

    assert signal_samples
    assert timeline
    assert detected_events
