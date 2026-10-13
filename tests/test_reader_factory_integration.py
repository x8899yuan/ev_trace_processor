from pathlib import Path

import pytest

from readers.blf_reader import BlfReader
from readers.dlt_reader import DltReader
from readers.pcap_reader import PcapReader
from readers.reader_factory import ReaderFactory


def test_selects_blf_reader() -> None:
    reader = ReaderFactory.get_reader(
        Path("vehicle_trace.blf")
    )

    assert isinstance(
        reader,
        BlfReader,
    )


def test_selects_pcap_reader() -> None:
    reader = ReaderFactory.get_reader(
        Path("network_capture.pcap")
    )

    assert isinstance(
        reader,
        PcapReader,
    )


def test_selects_dlt_reader() -> None:
    reader = ReaderFactory.get_reader(
        Path("vehicle_trace.dlt")
    )

    assert isinstance(
        reader,
        DltReader,
    )


def test_blf_extension_case_insensitive() -> None:
    reader = ReaderFactory.get_reader(
        Path("vehicle_trace.BLF")
    )

    assert isinstance(
        reader,
        BlfReader,
    )


def test_pcap_extension_case_insensitive() -> None:
    reader = ReaderFactory.get_reader(
        Path("capture.PCAP")
    )

    assert isinstance(
        reader,
        PcapReader,
    )


def test_dlt_extension_case_insensitive() -> None:
    reader = ReaderFactory.get_reader(
        Path("trace.DLT")
    )

    assert isinstance(
        reader,
        DltReader,
    )


def test_unsupported_extension_raises_value_error() -> None:
    with pytest.raises(ValueError):
        ReaderFactory.get_reader(
            Path("unsupported.xyz")
        )