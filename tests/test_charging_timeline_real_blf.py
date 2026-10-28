from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_timeline_service import ChargingTimelineService
from services.dbc_decoder_service import DbcDecoderService
from services.signal_extraction_service import SignalExtractionService


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEST_SIGNAL = "NVEM_IBatt"


def find_file(file_name: str) -> Path:
    matches = list(PROJECT_ROOT.rglob(file_name))
    assert matches, f"File not found: {file_name}"
    return matches[0]


def test_charging_timeline_real_blf() -> None:
    blf_file = find_file(
        "VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
    )
    dbc_file = find_file(
        "E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
    )

    reader = BlfReader()
    events = reader.read_events(
        blf_file,
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
                dbc_file,
                arbitration_id,
            ):
                continue

            decoded_message = decoder.decode_can_message(
                dbc_file=dbc_file,
                timestamp=event.timestamp.timestamp(),
                channel=event.payload.get("channel", 0),
                arbitration_id=arbitration_id,
                data=bytes.fromhex(data_hex),
            )
            decoded_messages.append(decoded_message)
        except Exception:
            continue

    assert decoded_messages
    assert decoded_messages[0].timestamp != 0.0

    extraction_service = SignalExtractionService()
    assert extraction_service.signal_exists(
        decoded_messages,
        TEST_SIGNAL,
    )

    samples = extraction_service.extract(
        decoded_messages,
        TEST_SIGNAL,
    )
    assert samples
    assert all(sample["timestamp"] != 0.0 for sample in samples)

    timeline_service = ChargingTimelineService()
    timeline = timeline_service.build_timeline(
        {TEST_SIGNAL: samples}
    )

    assert timeline
    assert all(entry["timestamp"] != 0.0 for entry in timeline)
