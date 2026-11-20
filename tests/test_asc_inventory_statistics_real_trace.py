from pathlib import Path

import pytest

from readers.asc_reader import AscReader
from services.asc_inventory_service import AscInventoryService
from services.asc_statistics_service import AscStatisticsService


ASC_FILES = sorted(Path("data/asc").glob("*.asc"))


@pytest.fixture(scope="module")
def real_trace():
    if not ASC_FILES:
        pytest.skip("No ASC fixture is present in data/asc")
    return AscReader().read(ASC_FILES[0])


def test_real_asc_inventory(real_trace):
    inventory = AscInventoryService().analyze(real_trace)
    assert inventory["message_count"] > 0
    assert inventory["classic_can_count"] > 0
    assert inventory["can_fd_count"] > 0
    assert inventory["unique_can_id_count"] > 0
    assert inventory["channels"]
    assert inventory["other_record_counts"].get("ethernet", 0) > 0
    assert inventory["other_record_counts"].get("lin", 0) > 0


def test_real_asc_statistics(real_trace):
    statistics = AscStatisticsService().analyze(real_trace)
    assert statistics["message_count"] == len(real_trace.messages)
    assert statistics["last_timestamp"] >= statistics["first_timestamp"]
    assert statistics["duration_seconds"] >= 0
    assert statistics["data_bytes"] > 0
    assert statistics["average_payload_bytes"] > 0
    assert statistics["top_can_ids"]
