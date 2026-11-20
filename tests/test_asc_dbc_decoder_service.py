from pathlib import Path

import pytest

from readers.asc_reader import AscMessage, AscTrace
from services.asc_dbc_decoder_service import AscDbcDecoderService


class FakeSignal:
    def __init__(self, name):
        self.name = name


class FakeMessage:
    def __init__(self, frame_id, name, decoded=None, error=None):
        self.frame_id = frame_id
        self.name = name
        self.decoded = decoded or {}
        self.error = error
        self.signals = [FakeSignal(signal_name) for signal_name in self.decoded]

    def decode(self, data, decode_choices=True):
        if self.error:
            raise self.error
        return self.decoded


class FakeDatabase:
    def __init__(self, messages):
        self._messages = messages
        self.messages = list(messages.values())

    def get_message_by_frame_id(self, frame_id):
        if frame_id not in self._messages:
            raise KeyError(frame_id)
        return self._messages[frame_id]


def message(timestamp, frame_id, data=b"\x00" * 8, channel=1, is_fd=False):
    return AscMessage(timestamp, channel, frame_id, False, "Rx", 8, len(data), data, is_fd)


def test_decode_preserves_signal_provenance_and_counts():
    trace = AscTrace(
        source_file=Path("sample.asc"),
        messages=[
            message(1.0, 0x100),
            message(1.1, 0x100, channel=2, is_fd=True),
            message(1.2, 0x777),
        ],
    )
    database = FakeDatabase(
        {
            0x100: FakeMessage(
                0x100,
                "ChargingStatus",
                {
                    "HVLM_Ladevorgang_Anf": "Laden_nicht_angefordert",
                    "HVLM_CP_MaxStrom_A": 0.0,
                },
            )
        }
    )
    result = AscDbcDecoderService(database).decode(trace)
    assert result["message_count"] == 3
    assert result["matched_message_count"] == 2
    assert result["decoded_message_count"] == 2
    assert result["unmatched_message_count"] == 1
    assert result["decoded_signal_count"] == 4
    assert result["unique_decoded_message_count"] == 1
    assert result["unique_decoded_signal_count"] == 2
    assert result["message_name_counts"] == {"ChargingStatus": 2}
    assert result["unmatched_can_ids"] == [{"arbitration_id": 0x777, "hex_id": "0x777", "count": 1}]
    assert result["target_signal_filter_applied"] is False
    assert result["requested_signals"] == []
    first = result["signal_samples"][0]
    assert first["timestamp"] == 1.0
    assert first["channel"] == 1
    assert first["hex_id"] == "0x100"
    assert first["message_name"] == "ChargingStatus"
    assert first["signal_name"] == "HVLM_Ladevorgang_Anf"


def test_decode_failures_are_counted_without_stopping_trace():
    trace = AscTrace(source_file=Path("sample.asc"), messages=[message(1.0, 0x200), message(1.1, 0x201)])
    database = FakeDatabase(
        {
            0x200: FakeMessage(0x200, "Broken", error=ValueError("payload mismatch")),
            0x201: FakeMessage(0x201, "Good", {"Signal": 7}),
        }
    )
    result = AscDbcDecoderService(database).decode(trace)
    assert result["matched_message_count"] == 2
    assert result["decoded_message_count"] == 1
    assert result["decode_failure_count"] == 1
    assert result["decode_failure_can_ids"] == [{"arbitration_id": 0x200, "hex_id": "0x200", "count": 1}]
    assert result["signal_samples"][0]["value"] == 7


def test_target_signal_filter_returns_only_requested_signals_and_skips_irrelevant_messages():
    trace = AscTrace(
        source_file=Path("sample.asc"),
        messages=[
            message(1.0, 0x100),
            message(1.1, 0x200),
            message(1.2, 0x777),
        ],
    )
    database = FakeDatabase(
        {
            0x100: FakeMessage(
                0x100,
                "ChargingStatus",
                {
                    "HVLM_Ladevorgang_Anf": "DC_Laden_Angefordert",
                    "UnrelatedSignal": 15,
                },
            ),
            0x200: FakeMessage(0x200, "UnrelatedMessage", {"OtherSignal": 99}),
        }
    )
    result = AscDbcDecoderService(database).decode(
        trace,
        target_signals={"HVLM_Ladevorgang_Anf"},
    )
    assert result["target_signal_filter_applied"] is True
    assert result["requested_signals"] == ["HVLM_Ladevorgang_Anf"]
    assert result["message_count"] == 3
    assert result["filtered_message_count"] == 2
    assert result["matched_message_count"] == 1
    assert result["decoded_message_count"] == 1
    assert result["decoded_signal_count"] == 1
    assert result["unique_decoded_message_count"] == 1
    assert result["unique_decoded_signal_count"] == 1
    assert result["message_name_counts"] == {"ChargingStatus": 1}
    assert result["signal_samples"] == [
        {
            "timestamp": 1.0,
            "channel": 1,
            "arbitration_id": 0x100,
            "hex_id": "0x100",
            "is_extended_id": False,
            "direction": "Rx",
            "is_fd": False,
            "message_name": "ChargingStatus",
            "signal_name": "HVLM_Ladevorgang_Anf",
            "value": "DC_Laden_Angefordert",
        }
    ]


def test_empty_target_signal_filter_decodes_nothing():
    trace = AscTrace(
        source_file=Path("sample.asc"),
        messages=[message(1.0, 0x100), message(1.1, 0x200)],
    )
    database = FakeDatabase(
        {
            0x100: FakeMessage(0x100, "ChargingStatus", {"SignalA": 1}),
            0x200: FakeMessage(0x200, "OtherStatus", {"SignalB": 2}),
        }
    )
    result = AscDbcDecoderService(database).decode(trace, target_signals=set())
    assert result["target_signal_filter_applied"] is True
    assert result["requested_signals"] == []
    assert result["filtered_message_count"] == 2
    assert result["matched_message_count"] == 0
    assert result["decoded_message_count"] == 0
    assert result["decoded_signal_count"] == 0
    assert result["unique_decoded_message_count"] == 0
    assert result["unique_decoded_signal_count"] == 0
    assert result["signal_samples"] == []


def test_missing_dbc_file_raises_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="DBC file not found"):
        AscDbcDecoderService().decode(AscTrace(source_file=Path("sample.asc")), tmp_path / "missing.dbc")


def test_database_or_dbc_is_required():
    with pytest.raises(ValueError, match="DBC file is required"):
        AscDbcDecoderService().decode(AscTrace(source_file=Path("sample.asc")))
