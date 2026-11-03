from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from models.trace_event import TraceEvent
from readers.dlt_reader import DltReader


def test_supports_dlt_extension():
    reader = DltReader()

    assert reader.supports(Path("trace.dlt"))
    assert reader.supports(Path("trace.DLT"))
    assert not reader.supports(Path("trace.blf"))
    assert not reader.supports(Path("trace.pcap"))


def test_invalid_max_events():
    with pytest.raises(ValueError):
        DltReader(max_events=0)

    with pytest.raises(ValueError):
        DltReader(max_events=-1)


def test_missing_file(tmp_path):
    reader = DltReader()
    file_path = tmp_path / "missing.dlt"

    with pytest.raises(FileNotFoundError):
        reader.read(file_path)


def test_rejects_non_file_path(tmp_path):
    reader = DltReader()
    directory = tmp_path / "trace.dlt"
    directory.mkdir()

    with pytest.raises(ValueError):
        reader.read(directory)


def test_rejects_unsupported_extension(tmp_path):
    reader = DltReader()
    file_path = tmp_path / "trace.blf"
    file_path.write_bytes(b"")

    with pytest.raises(ValueError):
        reader.read(file_path)


def test_reads_empty_dlt_file(tmp_path):
    reader = DltReader()
    file_path = tmp_path / "empty.dlt"
    file_path.write_bytes(b"")

    trace = reader.read(file_path)

    assert trace.metadata.file_path == file_path
    assert trace.metadata.trace_type == "DLT"
    assert trace.metadata.file_size_bytes == 0
    assert trace.metadata.start_timestamp is None
    assert trace.metadata.end_timestamp is None
    assert trace.metadata.event_count == 0
    assert trace.event_count == 0
    assert trace.is_empty

    assert reader.last_read_stats == {
        "decoded_records": 0,
        "skipped_records": 0,
        "resynchronizations": 0,
        "event_count": 0,
    }


def test_max_events_limits_result(tmp_path):
    reader = DltReader(max_events=1)
    file_path = tmp_path / "limited.dlt"

    record = _make_record()
    file_path.write_bytes(record + record)

    trace = reader.read(file_path)

    assert trace.event_count == 1
    assert trace.metadata.event_count == 1
    assert reader.last_read_stats["decoded_records"] == 1
    assert reader.last_read_stats["event_count"] == 1


def test_non_verbose_message_normalization(tmp_path):
    reader = DltReader()
    file_path = tmp_path / "non_verbose.dlt"
    file_path.write_bytes(_make_record())

    message = _make_non_verbose_message()

    with patch(
        "readers.dlt_reader.DltMessage.create_from_bytes",
        return_value=message,
    ):
        trace = reader.read(file_path)

    assert trace.event_count == 1

    event = trace.events[0]

    assert isinstance(event, TraceEvent)
    assert event.timestamp == datetime(
        2026,
        5,
        11,
        4,
        34,
        53,
        725090,
        tzinfo=timezone.utc,
    )
    assert event.source_type == "DLT"
    assert event.event_name == "LOG.LTDC"
    assert event.payload["ecu_id"] == "8123"
    assert event.payload["application_id"] == "LOG"
    assert event.payload["context_id"] == "LTDC"
    assert event.payload["message_counter"] == 0
    assert event.payload["message_length"] == 32
    assert event.payload["dlt_timestamp"] == 11494696
    assert event.payload["verbose"] is False
    assert event.payload["message_type"] == 3
    assert event.payload["message_type_info"] == 2
    assert event.payload["number_of_arguments"] == 1
    assert event.payload["message_id"] == 3842
    assert event.payload["non_static_data_hex"] == "000200000000"


def test_verbose_message_normalization(tmp_path):
    reader = DltReader()
    file_path = tmp_path / "verbose.dlt"
    file_path.write_bytes(_make_record())

    message = _make_verbose_message()

    with patch(
        "readers.dlt_reader.DltMessage.create_from_bytes",
        return_value=message,
    ):
        trace = reader.read(file_path)

    event = trace.events[0]

    assert event.source_type == "DLT"
    assert event.event_name == "PRM.DFLT"
    assert event.payload["ecu_id"] == "8123"
    assert event.payload["application_id"] == "PRM"
    assert event.payload["context_id"] == "DFLT"
    assert event.payload["verbose"] is True

    assert event.payload["arguments"] == [
        {
            "type": "ArgumentString",
            "value": "Sending alive supervision for ID ",
        },
        {
            "type": "ArgumentUInt16",
            "value": 10002,
        },
        {
            "type": "ArgumentString",
            "value": ", checkpoint ",
        },
        {
            "type": "ArgumentUInt16",
            "value": 1,
        },
    ]


def test_metadata_uses_first_and_last_event_timestamps(tmp_path):
    reader = DltReader()
    file_path = tmp_path / "timestamps.dlt"

    record = _make_record()
    file_path.write_bytes(record + record)

    first = _make_non_verbose_message(
        seconds=100,
        microseconds=100000,
    )
    second = _make_non_verbose_message(
        seconds=200,
        microseconds=200000,
    )

    with patch(
        "readers.dlt_reader.DltMessage.create_from_bytes",
        side_effect=[first, second],
    ):
        trace = reader.read(file_path)

    assert trace.event_count == 2
    assert trace.metadata.event_count == 2

    assert trace.metadata.start_timestamp == datetime(
        1970,
        1,
        1,
        0,
        1,
        40,
        100000,
        tzinfo=timezone.utc,
    )

    assert trace.metadata.end_timestamp == datetime(
        1970,
        1,
        1,
        0,
        3,
        20,
        200000,
        tzinfo=timezone.utc,
    )


def test_skips_decode_failure_and_continues(tmp_path):
    reader = DltReader()
    file_path = tmp_path / "unsupported.dlt"

    record = _make_record()
    file_path.write_bytes(record + record)

    valid_message = _make_non_verbose_message()

    with patch(
        "readers.dlt_reader.DltMessage.create_from_bytes",
        side_effect=[
            ValueError("Unsupported TypeInfo"),
            valid_message,
        ],
    ):
        trace = reader.read(file_path)

    assert trace.event_count == 1
    assert reader.last_read_stats["decoded_records"] == 1
    assert reader.last_read_stats["skipped_records"] == 1


def test_resynchronizes_to_storage_header(tmp_path):
    reader = DltReader()
    file_path = tmp_path / "resync.dlt"

    file_path.write_bytes(
        b"garbage-before-dlt-record" + _make_record()
    )

    message = _make_non_verbose_message()

    with patch(
        "readers.dlt_reader.DltMessage.create_from_bytes",
        return_value=message,
    ):
        trace = reader.read(file_path)

    assert trace.event_count == 1
    assert reader.last_read_stats["resynchronizations"] == 1


def test_last_read_stats_for_successful_records(tmp_path):
    reader = DltReader()
    file_path = tmp_path / "stats.dlt"

    record = _make_record()
    file_path.write_bytes(record + record)

    with patch(
        "readers.dlt_reader.DltMessage.create_from_bytes",
        side_effect=[
            _make_non_verbose_message(),
            _make_verbose_message(),
        ],
    ):
        trace = reader.read(file_path)

    assert trace.event_count == 2

    assert reader.last_read_stats == {
        "decoded_records": 2,
        "skipped_records": 0,
        "resynchronizations": 0,
        "event_count": 2,
    }


class FakeObject:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class ArgumentString:
    def __init__(self, data):
        self.data = data


class ArgumentUInt16:
    def __init__(self, data):
        self.data = data


def _make_record() -> bytes:
    storage_header = b"DLT\x01" + bytes(12)

    standard_header = bytes(
        [
            0x00,
            0x00,
            0x00,
            0x04,
        ]
    )

    return storage_header + standard_header


def _make_non_verbose_message(
    seconds=1778474093,
    microseconds=725090,
):
    return FakeObject(
        str_header=FakeObject(
            seconds=seconds,
            microseconds=microseconds,
            ecu_id="8123",
        ),
        std_header=FakeObject(
            message_counter=0,
            length=32,
            timestamp=11494696,
            ecu_id="8123",
        ),
        ext_header=FakeObject(
            verbose=False,
            message_type=3,
            message_type_info=2,
            number_of_arguments=1,
            application_id="LOG",
            context_id="LTDC",
        ),
        payload=FakeObject(
            message_id=3842,
            non_static_data=b"\x00\x02\x00\x00\x00\x00",
        ),
    )


def _make_verbose_message():
    return FakeObject(
        str_header=FakeObject(
            seconds=1778474093,
            microseconds=762090,
            ecu_id="8123",
        ),
        std_header=FakeObject(
            message_counter=202,
            length=100,
            timestamp=11505927,
            ecu_id="8123",
        ),
        ext_header=FakeObject(
            verbose=True,
            message_type=0,
            message_type_info=4,
            number_of_arguments=4,
            application_id="PRM",
            context_id="DFLT",
        ),
        payload=FakeObject(
            arguments=[
                ArgumentString(
                    "Sending alive supervision for ID "
                ),
                ArgumentUInt16(10002),
                ArgumentString(", checkpoint "),
                ArgumentUInt16(1),
            ]
        ),
    )