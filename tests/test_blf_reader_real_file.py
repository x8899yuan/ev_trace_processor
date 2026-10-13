from pathlib import Path

import pytest

from readers.blf_reader import BlfReader


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)


def test_real_blf_file_exists() -> None:
    if not BLF_FILE.exists():
        pytest.skip(
            f"BLF file not available: {BLF_FILE}"
        )

    assert BLF_FILE.exists()


def test_real_blf_has_messages() -> None:
    if not BLF_FILE.exists():
        pytest.skip(
            f"BLF file not available: {BLF_FILE}"
        )

    reader = BlfReader()

    count = reader.get_message_count(
        BLF_FILE
    )

    assert count > 0