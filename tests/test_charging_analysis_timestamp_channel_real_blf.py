from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_analysis_service import ChargingAnalysisService
from services.dbc_decoder_service import DbcDecoderService


BLF_FILE = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")
DBC_FILE = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")


def test_charging_analysis_preserves_timestamp_and_channel(
    monkeypatch,
) -> None:
    assert BLF_FILE.exists(), f"Missing BLF file: {BLF_FILE}"
    assert DBC_FILE.exists(), f"Missing DBC file: {DBC_FILE}"

    reader = BlfReader()
    events = reader.read_events(BLF_FILE, max_events=10000)
    decoder = DbcDecoderService()

    target_ids = ChargingAnalysisService()._find_target_ids(
        decoder,
        DBC_FILE,
    )

    expected_timestamp = None
    expected_channel = None
    expected_arbitration_id = None

    for event in events:
        arbitration_id = event.payload.get("arbitration_id")
        data_hex = event.payload.get("data")

        if arbitration_id not in target_ids or not data_hex:
            continue

        expected_timestamp = event.timestamp.timestamp()
        expected_channel = event.payload.get("channel", 0)
        expected_arbitration_id = arbitration_id
        break

    assert expected_timestamp is not None
    assert expected_channel is not None
    assert expected_arbitration_id is not None

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
    assert captured_calls[0]["channel"] == expected_channel
    assert captured_calls[0]["arbitration_id"] == expected_arbitration_id
