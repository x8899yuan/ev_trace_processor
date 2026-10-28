from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_analysis_service import ChargingAnalysisService
from services.dbc_decoder_service import DbcDecoderService


PROJECT_ROOT = Path(__file__).resolve().parent.parent
BLF_FILE = (
    PROJECT_ROOT
    / "data"
    / "blf"
    / "VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)
DBC_FILE = (
    PROJECT_ROOT
    / "dbc"
    / "E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)


def test_charging_analysis_preserves_timestamp_and_channel(
    monkeypatch,
) -> None:
    assert BLF_FILE.exists(), f"Missing BLF file: {BLF_FILE}"
    assert DBC_FILE.exists(), f"Missing DBC file: {DBC_FILE}"

    reader = BlfReader()
    events = reader.read_events(BLF_FILE, max_events=10000)
    decoder = DbcDecoderService()

    expected_timestamp = None
    expected_channel = None

    for event in events:
        arbitration_id = event.payload.get("arbitration_id")
        data_hex = event.payload.get("data")

        if arbitration_id is None or not data_hex:
            continue

        if decoder.message_exists(DBC_FILE, arbitration_id):
            expected_timestamp = event.timestamp.timestamp()
            expected_channel = event.payload.get("channel", 0)
            break

    assert expected_timestamp is not None
    assert expected_channel is not None

    captured_calls = []
    original_decode = DbcDecoderService.decode_can_message

    def capture_decode(
        self,
        dbc_file,
        timestamp,
        channel,
        arbitration_id,
        data,
    ):
        captured_calls.append(
            {
                "timestamp": timestamp,
                "channel": channel,
                "arbitration_id": arbitration_id,
            }
        )
        return original_decode(
            self,
            dbc_file=dbc_file,
            timestamp=timestamp,
            channel=channel,
            arbitration_id=arbitration_id,
            data=data,
        )

    monkeypatch.setattr(
        DbcDecoderService,
        "decode_can_message",
        capture_decode,
    )

    ChargingAnalysisService().analyze(
        blf_file=BLF_FILE,
        dbc_file=DBC_FILE,
        max_events=10000,
    )

    assert captured_calls
    assert captured_calls[0]["timestamp"] == expected_timestamp
    assert captured_calls[0]["timestamp"] != 0.0
    assert captured_calls[0]["channel"] == expected_channel
