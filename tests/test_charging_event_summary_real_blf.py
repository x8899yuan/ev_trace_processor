from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_event_detection_service import (
    ChargingEventDetectionService,
)
from services.charging_event_summary_service import (
    ChargingEventSummaryService,
)
from services.charging_timeline_service import (
    ChargingTimelineService,
)
from services.dbc_decoder_service import (
    DbcDecoderService,
)
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


def test_charging_event_summary_real_blf() -> None:

    assert BLF_FILE.exists()
    assert DBC_FILE.exists()

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
                    timestamp=event.timestamp,
                    channel=event.payload.get(
                        "channel",
                        0,
                    ),
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

    assert decoded_messages

    extractor = SignalExtractionService()

    signal_samples = {}

    for signal_name in TEST_SIGNALS:

        samples = extractor.extract(
            decoded_messages,
            signal_name,
        )

        if samples:
            signal_samples[
                signal_name
            ] = samples

    timeline_service = (
        ChargingTimelineService()
    )

    timeline = (
        timeline_service.build_timeline(
            signal_samples
        )
    )

    event_detection_service = (
        ChargingEventDetectionService()
    )

    detected_events = (
        event_detection_service.detect_events(
            timeline
        )
    )

    print()
    print("FIRST EVENT")
    print("=" * 80)

    if detected_events:
        print(detected_events[0])

    summary_service = (
        ChargingEventSummaryService()
    )

    summary_text = (
        summary_service.generate_summary(
            detected_events
        )
    )

    output_dir = Path(
        r"reports\charging"
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary_file = (
        output_dir
        / "charging_event_summary.txt"
    )

    summary_service.save_summary(
        summary_text,
        summary_file,
    )

    print()
    print(
        f"Decoded Messages: "
        f"{len(decoded_messages)}"
    )

    print()
    print(
        f"Detected Events: "
        f"{len(detected_events)}"
    )

    print()
    print(
        f"Summary File: "
        f"{summary_file}"
    )

    print()
    print("Summary Preview")
    print("=" * 80)
    print(summary_text)

    assert summary_file.exists()
    assert len(detected_events) > 0
    assert "Charging Event Summary" in summary_text