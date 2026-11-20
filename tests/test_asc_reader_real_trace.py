from pathlib import Path

import pytest

from readers.asc_reader import AscReader


ASC_FILES = sorted(Path("data/asc").glob("*.asc"))


def test_real_asc_reader_parses_can_and_canfd_records():
    if not ASC_FILES:
        pytest.skip("No ASC fixture is present in data/asc")
    trace = AscReader().read(ASC_FILES[0])
    assert trace.messages
    assert trace.record_counts.get("can", 0) > 0
    assert trace.record_counts.get("can_fd", 0) > 0
    assert trace.start_time is not None
    assert trace.numeric_base == "hex"
    assert trace.timestamp_mode == "absolute"
    assert all(message.data_length == len(message.data) for message in trace.messages)
    assert any(message.is_extended_id for message in trace.messages)
    assert any(not message.is_extended_id for message in trace.messages)


def test_real_asc_reader_tracks_other_bus_records():
    if not ASC_FILES:
        pytest.skip("No ASC fixture is present in data/asc")
    trace = AscReader().read(ASC_FILES[0])
    assert trace.record_counts.get("ethernet", 0) > 0
    assert trace.record_counts.get("lin", 0) > 0
