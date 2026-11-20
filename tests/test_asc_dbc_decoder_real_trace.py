from pathlib import Path

import pytest

from readers.asc_reader import AscReader
from services.asc_dbc_decoder_service import AscDbcDecoderService


ASC_FILES = sorted(Path("data/asc").glob("*.asc"))
DBC_FILE = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")


def test_real_asc_decodes_with_project_dbc():
    if not ASC_FILES:
        pytest.skip("No ASC fixture is present in data/asc")
    if not DBC_FILE.exists():
        pytest.skip(f"Project DBC fixture is not available: {DBC_FILE}")
    trace = AscReader().read(ASC_FILES[0])
    result = AscDbcDecoderService().decode(trace, DBC_FILE)
    assert result["message_count"] == len(trace.messages)
    assert result["matched_message_count"] > 0
    assert result["decoded_message_count"] > 0
    assert result["decoded_signal_count"] > 0
    assert result["message_name_counts"]
    assert result["signal_samples"]
    assert all("timestamp" in sample for sample in result["signal_samples"])
    assert all("channel" in sample for sample in result["signal_samples"])
    assert all("message_name" in sample for sample in result["signal_samples"])
    assert all("signal_name" in sample for sample in result["signal_samples"])
