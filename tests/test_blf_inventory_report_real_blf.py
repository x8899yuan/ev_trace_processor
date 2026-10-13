from pathlib import Path

from readers.blf_reader import BlfReader
from services.blf_inventory_report_service import (
    BlfInventoryReportService,
)
from services.blf_inventory_service import (
    BlfInventoryService,
)


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)


def test_real_blf_report() -> None:

    trace = BlfReader().read(
        BLF_FILE,
    )

    inventory = (
        BlfInventoryService()
        .analyze(trace)
    )

    report_service = (
        BlfInventoryReportService()
    )

    report = (
        report_service
        .generate_report(
            inventory
        )
    )

    print()
    print(report)

    assert "BLF Inventory Report" in report
    assert "Total Frames:" in report
    assert "Unique CAN IDs:" in report
    assert "Top CAN IDs" in report

    report_path = (
        report_service
        .save_report(
            inventory,
            BLF_FILE.name,
        )
    )

    assert report_path.exists()

    assert (
        report_path.suffix
        == ".txt"
    )

    assert (
        report_path.parent.name
        == "inventory"
    )

    saved_report = (
        report_path.read_text(
            encoding="utf-8",
        )
    )

    assert (
        "BLF Inventory Report"
        in saved_report
    )

    print()
    print(
        "Persistent Report Path:",
        report_path,
    )
    print()