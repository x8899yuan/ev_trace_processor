from pathlib import Path

from readers.asc_reader import AscMessage, AscTrace
from services.asc_statistics_service import AscStatisticsService


def test_statistics_calculates_timing_load_and_top_ids():
    trace = AscTrace(
        source_file=Path("sample.asc"),
        messages=[
            AscMessage(10.0, 1, 0x100, False, "Rx", 8, 8, bytes(8), False),
            AscMessage(10.5, 1, 0x100, False, "Rx", 8, 8, bytes(8), False),
            AscMessage(11.0, 2, 0x200, False, "Tx", 13, 32, bytes(32), True, True, False),
        ],
    )
    result = AscStatisticsService().analyze(trace, top_n=2)
    assert result["message_count"] == 3
    assert result["first_timestamp"] == 10.0
    assert result["last_timestamp"] == 11.0
    assert result["duration_seconds"] == 1.0
    assert result["messages_per_second"] == 3.0
    assert result["data_bytes"] == 48
    assert result["average_payload_bytes"] == 16.0
    assert result["top_can_ids"][0] == {"arbitration_id": 0x100, "hex_id": "0x100", "count": 2}
    assert result["channel_counts"] == {1: 2, 2: 1}
    assert result["direction_counts"] == {"Rx": 2, "Tx": 1}
    assert result["payload_length_counts"] == {8: 2, 32: 1}


def test_statistics_handles_empty_trace():
    result = AscStatisticsService().analyze(AscTrace(source_file=Path("empty.asc")))
    assert result["message_count"] == 0
    assert result["duration_seconds"] == 0.0
    assert result["messages_per_second"] == 0.0
    assert result["top_can_ids"] == []
