from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_signal_extraction_service import (
    ChargingSignalExtractionService,
)
from services.charging_timeline_service import (
    ChargingTimelineService,
)
from services.dbc_decoder_service import DbcDecoderService


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)

DBC_FILE = Path(
    r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)

TEST_SIGNAL = "NVEM_IBatt"


def test_charging_timeline_real_blf() -> None:

    assert BLF_FILE.exists(), (
        f"BLF file not found: {BLF_FILE}"
    )

    assert DBC_FILE.exists(), (
        f"DBC file not found: {DBC_FILE}"
    )

    reader = BlfReader()

    events = reader.read_events(
        BLF_FILE,
        max_events=10000,
    )

    decoder = DbcDecoderService()

    decoded_messages = []

    for event in events:

        arbitration_id = event.payload.get(
            "arbitration_id"
        )

        data_hex = event.payload.get(
            "data"
        )

        if arbitration_id is None:
            continue

        if not data_hex:
            continue

        try:

            if not decoder.message_exists(
                DBC_FILE,
                arbitration_id,
            ):
                continue

            decoded_message = (
                decoder.decode_can_message(
                    dbc_file=DBC_FILE,
                    timestamp=0.0,
                    channel=0,
                    arbitration_id=arbitration_id,
                    data=bytes.fromhex(
                        data_hex
                    ),
                )
            )

            decoded_messages.append(
                decoded_message
            )

        except Exception:
            continue

    extraction_service = (
        ChargingSignalExtractionService()
    )

    samples = (
        extraction_service.extract_signal(
            decoded_messages,
            TEST_SIGNAL,
        )
    )

    signal_samples = {
        TEST_SIGNAL: samples,
    }

    timeline_service = (
        ChargingTimelineService()
    )

    timeline = (
        timeline_service.build_timeline(
            signal_samples
        )
    )

    print()
    print("Charging Timeline")
    print("=" * 80)

    for event in timeline[:20]:

        print(
            f"{event['timestamp']} | "
            f"{event['signal']} | "
            f"{event['old_value']} -> "
            f"{event['new_value']}"
        )

    print()
    print(
        f"Timeline Events: "
        f"{len(timeline)}"
    )

    assert len(samples) > 0
    assert len(timeline) > 0