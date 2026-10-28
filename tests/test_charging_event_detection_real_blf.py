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

EXPECTED_EVENT_TYPES = {
    "CHARGING_PERMISSION_DENIED",
    "VEHICLE_NOT_READY",
    "CHARGING_READINESS_NOT_ACHIEVED",
    "HV_CONTACTOR_OPEN_OR_WELD_DETECTION",
    "CHARGING_NOT_REQUESTED",
    "CHARGING_STATE_MACHINE_ERROR",
}

EXPECTED_CATEGORIES = {
    "charging_inhibition",
    "charging_readiness",
    "high_voltage_system",
    "charging_request",
    "charging_state",
}


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
                timestamp=event.timestamp.timestamp(),
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

    assert signal_samples
    assert timeline
    assert detected_events

    for detected_event in detected_events:
        assert set(detected_event) == {
            "timestamp",
            "signal",
            "value",
            "description",
            "event_type",
            "category",
        }
        assert detected_event["timestamp"] != 0.0
        assert detected_event["signal"] in TEST_SIGNALS
        assert detected_event["description"]
        assert detected_event["event_type"] in EXPECTED_EVENT_TYPES
        assert detected_event["category"] in EXPECTED_CATEGORIES

    detected_event_types = {
        event["event_type"]
        for event in detected_events
    }

    detected_categories = {
        event["category"]
        for event in detected_events
    }

    assert detected_event_types <= EXPECTED_EVENT_TYPES
    assert detected_categories <= EXPECTED_CATEGORIES
