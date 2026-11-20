from pathlib import Path

from readers.asc_reader import AscMessage, AscTrace
from services.asc_inventory_service import AscInventoryService


def test_inventory_summarizes_trace_structure():
    trace = AscTrace(
        source_file=Path("sample.asc"),
        numeric_base="hex",
        timestamp_mode="absolute",
        messages=[
            AscMessage(1.0, 1, 0x123, False, "Rx", 8, 8, bytes(8), False),
            AscMessage(1.1, 2, 0x1B000010, True, "Tx", 8, 8, bytes(8), True, True, False),
            AscMessage(1.2, 1, 0x123, False, "Rx", 8, 8, bytes(8), False),
        ],
        record_counts={"can": 2, "can_fd": 1, "ethernet": 5, "lin": 3},
        ignored_line_count=8,
        malformed_line_count=2,
    )
    result = AscInventoryService().analyze(trace)
    assert result["message_count"] == 3
    assert result["classic_can_count"] == 2
    assert result["can_fd_count"] == 1
    assert result["standard_id_count"] == 2
    assert result["extended_id_count"] == 1
    assert result["unique_can_id_count"] == 2
    assert result["channels"] == {1: 2, 2: 1}
    assert result["directions"] == {"Rx": 2, "Tx": 1}
    assert result["other_record_counts"] == {"ethernet": 5, "lin": 3}
    assert result["ignored_line_count"] == 8
    assert result["malformed_line_count"] == 2
