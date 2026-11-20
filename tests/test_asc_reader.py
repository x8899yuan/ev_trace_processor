from pathlib import Path

from readers.asc_reader import AscReader


def test_parse_classic_can_message():
    message = AscReader().parse_line("44147.136259 10  1B000010x         Rx D 8   00  50  04  50  01  F7  30  00")
    assert message is not None
    assert message.timestamp == 44147.136259
    assert message.channel == 10
    assert message.arbitration_id == 0x1B000010
    assert message.is_extended_id is True
    assert message.direction == "Rx"
    assert message.dlc == 8
    assert message.data == bytes.fromhex("00 50 04 50 01 F7 30 00")
    assert message.is_fd is False


def test_parse_canfd_message_with_metadata_tail():
    message = AscReader().parse_line("44147.136348 CANFD 4 Rx 656       1 0 8 8 D3 8F 09 00 00 00 00 00 0 0 3000 0 0 0")
    assert message is not None
    assert message.channel == 4
    assert message.arbitration_id == 0x656
    assert message.is_extended_id is False
    assert message.brs is True
    assert message.esi is False
    assert message.dlc == 8
    assert message.data_length == 8
    assert message.data == bytes.fromhex("D3 8F 09 00 00 00 00 00")


def test_parse_canfd_32_byte_payload():
    line = "44147.137387 CANFD 8 Rx 271 1 0 D 32 00 00 00 00 25 FD 5B FD 8F 00 00 00 C0 6F F5 06 60 E5 01 00 00 00 00 00 00 00 00 00 60 3F 07 00 0 0 3000 0 0 0"
    message = AscReader().parse_line(line)
    assert message is not None
    assert message.dlc == 13
    assert message.data_length == 32
    assert len(message.data) == 32


def test_read_mixed_trace_and_count_unsupported_records(tmp_path):
    path = tmp_path / "sample.asc"
    path.write_text(
        "date Mon Mar 10 07:45:00 2025\n"
        "base hex timestamps absolute\n"
        "Begin Triggerblock\n"
        "44147.136259 10  1B000010x Rx D 8 00 50 04 50 01 F7 30 00\n"
        "44147.136348 CANFD 4 Rx 656 1 0 8 8 D3 8F 09 00 00 00 00 00 0 0 3000 0 0 0\n"
        "44147.136484 Li 34 Rx 8 0B 19 00 00 18 00 3A 4C checksum = 00\n"
        "44147.136865 ETH 21 Rx 52:333300000006\n",
        encoding="utf-8",
    )
    trace = AscReader().read(path)
    assert trace.source_file == path
    assert trace.start_time is not None
    assert trace.numeric_base == "hex"
    assert trace.timestamp_mode == "absolute"
    assert len(trace.messages) == 2
    assert trace.record_counts == {"can": 1, "can_fd": 1, "lin": 1, "ethernet": 1}
    assert trace.ignored_line_count == 2
    assert trace.malformed_line_count == 0


def test_missing_file_raises_clear_error(tmp_path):
    path = tmp_path / "missing.asc"
    try:
        AscReader().read(path)
    except FileNotFoundError as error:
        assert str(path) in str(error)
    else:
        raise AssertionError("Expected FileNotFoundError")
