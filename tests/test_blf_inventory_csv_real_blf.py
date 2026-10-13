from pathlib import Path

from readers.blf_reader import BlfReader
from services.blf_inventory_csv_service import (
    BlfInventoryCsvService,
)
from services.blf_inventory_service import (
    BlfInventoryService,
)


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)


def test_real_blf_csv_export(
    tmp_path: Path,
) -> None:

    trace = BlfReader().read(
        BLF_FILE,
    )

    inventory = (
        BlfInventoryService()
        .analyze(trace)
    )

    csv_service = (
        BlfInventoryCsvService()
    )

    output_file = (
        tmp_path / "inventory.csv"
    )

    result = csv_service.export(
        inventory,
        output_file,
    )

    assert result.exists()

    content = result.read_text(
        encoding="utf-8",
    )

    print()
    print("Temporary CSV Path:", result)
    print()

    lines = content.splitlines()

    print(
        "\n".join(
            lines[:10]
        )
    )

    assert (
        "CAN_ID,Frames,Channel,Extended"
        in content
    )

    assert len(lines) > 1

    persistent_csv = (
        csv_service.save_csv(
            inventory,
            BLF_FILE.name,
        )
    )

    assert persistent_csv.exists()
    assert persistent_csv.suffix == ".csv"
    assert (
        persistent_csv.parent.name
        == "inventory"
    )

    print()
    print(
        "Persistent CSV Path:",
        persistent_csv,
    )
    print()