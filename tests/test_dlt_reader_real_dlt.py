from pathlib import Path

import pytest

from readers.dlt_reader import DltReader


DLT_DIRECTORY = Path("data") / "dlt"
SAMPLE_SIZE = 1000

DLT_FILES = [
    (
        "VW31666_0173_20260508_140000h_DLT_ICAS1_AdaptiveVM.dlt",
        "8123",
    ),
    (
        "VW31666_0173_20260508_140000h_DLT_ICAS1_HousekeepingVM.dlt",
        "C003",
    ),
    (
        "VW31666_0173_20260508_140000h_DLT_ICAS1_JavaVM.dlt",
        "8124",
    ),
    (
        "VW31666_0173_20260508_140000h_DLT_ICAS1_R7.dlt",
        "C002",
    ),
]


def get_file(file_name):
    file_path = DLT_DIRECTORY / file_name

    if not file_path.exists():
        pytest.skip(f"Real DLT file not available: {file_path}")

    return file_path


@pytest.mark.parametrize(
    "file_name,expected_ecu",
    DLT_FILES,
)
def test_real_dlt_reads_bounded_sample(
    file_name,
    expected_ecu,
):
    file_path = get_file(file_name)
    reader = DltReader(max_events=SAMPLE_SIZE)

    trace = reader.read(file_path)

    assert trace.event_count == SAMPLE_SIZE
    assert trace.metadata.event_count == SAMPLE_SIZE
    assert not trace.is_empty

    assert trace.metadata.file_path == file_path
    assert trace.metadata.file_name == file_name
    assert trace.metadata.trace_type == "DLT"
    assert trace.metadata.file_size_bytes == file_path.stat().st_size

    assert trace.metadata.start_timestamp is not None
    assert trace.metadata.end_timestamp is not None
    assert (
        trace.metadata.end_timestamp
        >= trace.metadata.start_timestamp
    )

    assert reader.last_read_stats["decoded_records"] == SAMPLE_SIZE
    assert reader.last_read_stats["event_count"] == SAMPLE_SIZE

    assert all(
        event.source_type == "DLT"
        for event in trace.events
    )

    assert all(
        event.payload["ecu_id"] == expected_ecu
        for event in trace.events
    )


@pytest.mark.parametrize(
    "file_name,expected_ecu",
    DLT_FILES,
)
def test_real_dlt_preserves_header_fields(
    file_name,
    expected_ecu,
):
    file_path = get_file(file_name)
    reader = DltReader(max_events=SAMPLE_SIZE)

    trace = reader.read(file_path)

    for event in trace.events:
        assert event.payload["ecu_id"] == expected_ecu
        assert "application_id" in event.payload
        assert "context_id" in event.payload
        assert "message_counter" in event.payload
        assert "message_length" in event.payload
        assert "dlt_timestamp" in event.payload
        assert "verbose" in event.payload
        assert "message_type" in event.payload
        assert "message_type_info" in event.payload
        assert "number_of_arguments" in event.payload
        assert "message" in event.payload


@pytest.mark.parametrize(
    "file_name,_",
    DLT_FILES,
)
def test_real_dlt_event_names_are_populated(
    file_name,
    _,
):
    file_path = get_file(file_name)
    reader = DltReader(max_events=SAMPLE_SIZE)

    trace = reader.read(file_path)

    assert all(
        event.event_name
        for event in trace.events
    )


@pytest.mark.parametrize(
    "file_name,_",
    DLT_FILES,
)
def test_real_dlt_timestamps_are_ordered(
    file_name,
    _,
):
    file_path = get_file(file_name)
    reader = DltReader(max_events=SAMPLE_SIZE)

    trace = reader.read(file_path)

    timestamps = [
        event.timestamp
        for event in trace.events
    ]

    assert timestamps == sorted(timestamps)


@pytest.mark.parametrize(
    "file_name,_",
    DLT_FILES[:3],
)
def test_real_vm_dlt_contains_verbose_messages(
    file_name,
    _,
):
    file_path = get_file(file_name)
    reader = DltReader(max_events=SAMPLE_SIZE)

    trace = reader.read(file_path)

    verbose_events = [
        event
        for event in trace.events
        if event.payload["verbose"] is True
    ]

    assert verbose_events

    assert any(
        "arguments" in event.payload
        for event in verbose_events
    )


@pytest.mark.parametrize(
    "file_name,_",
    DLT_FILES[:3],
)
def test_real_vm_dlt_contains_non_verbose_messages(
    file_name,
    _,
):
    file_path = get_file(file_name)
    reader = DltReader(max_events=SAMPLE_SIZE)

    trace = reader.read(file_path)

    non_verbose_events = [
        event
        for event in trace.events
        if event.payload["verbose"] is False
    ]

    assert non_verbose_events

    assert any(
        "message_id" in event.payload
        for event in non_verbose_events
    )

    assert any(
        "non_static_data_hex" in event.payload
        for event in non_verbose_events
    )


def test_real_r7_preserves_non_verbose_payload():
    file_name, expected_ecu = DLT_FILES[3]
    file_path = get_file(file_name)

    reader = DltReader(max_events=SAMPLE_SIZE)
    trace = reader.read(file_path)

    non_verbose_events = [
        event
        for event in trace.events
        if event.payload["verbose"] is False
    ]

    assert non_verbose_events
    assert len(non_verbose_events) > len(trace.events) / 2

    first = non_verbose_events[0]

    assert first.payload["ecu_id"] == expected_ecu
    assert "message_id" in first.payload
    assert "non_static_data_hex" in first.payload

    assert isinstance(
        first.payload["message_id"],
        int,
    )

    assert isinstance(
        first.payload["non_static_data_hex"],
        str,
    )

    assert first.payload["non_static_data_hex"]


def test_real_adaptive_vm_first_message():
    file_name, _ = DLT_FILES[0]
    file_path = get_file(file_name)

    reader = DltReader(max_events=1)
    trace = reader.read(file_path)

    event = trace.events[0]

    assert event.payload["ecu_id"] == "8123"
    assert event.payload["application_id"] == "LOG"
    assert event.payload["context_id"] == "LTDC"
    assert event.payload["verbose"] is False
    assert event.payload["message_id"] == 3842
    assert (
        event.payload["non_static_data_hex"]
        == "000200000000"
    )


def test_real_housekeeping_vm_first_message():
    file_name, _ = DLT_FILES[1]
    file_path = get_file(file_name)

    reader = DltReader(max_events=1)
    trace = reader.read(file_path)

    event = trace.events[0]

    assert event.payload["ecu_id"] == "C003"
    assert event.payload["application_id"] == "LOG"
    assert event.payload["context_id"] == "LTDC"
    assert event.payload["message_id"] == 3842


def test_real_java_vm_first_message():
    file_name, _ = DLT_FILES[2]
    file_path = get_file(file_name)

    reader = DltReader(max_events=1)
    trace = reader.read(file_path)

    event = trace.events[0]

    assert event.payload["ecu_id"] == "8124"
    assert event.payload["application_id"] == "LOG"
    assert event.payload["context_id"] == "LTDC"
    assert event.payload["message_id"] == 3842


def test_real_r7_first_message():
    file_name, _ = DLT_FILES[3]
    file_path = get_file(file_name)

    reader = DltReader(max_events=1)
    trace = reader.read(file_path)

    event = trace.events[0]

    assert event.payload["ecu_id"] == "C002"
    assert event.payload["application_id"] == "ASR4"
    assert event.payload["context_id"] == "Info"
    assert event.payload["verbose"] is False
    assert event.payload["message_id"] == 538976288
    assert event.payload["non_static_data_hex"]