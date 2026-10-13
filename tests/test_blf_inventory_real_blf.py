from pathlib import Path

from readers.blf_reader import BlfReader
from services.blf_inventory_service import BlfInventoryService


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)


def test_real_blf_inventory() -> None:

    reader = BlfReader()

    trace = reader.read(BLF_FILE)

    inventory = BlfInventoryService().analyze(trace)

    assert inventory.total_frames > 0
    assert inventory.unique_can_ids > 0
    assert len(inventory.channels) > 0
    assert len(inventory.can_id_statistics) > 0