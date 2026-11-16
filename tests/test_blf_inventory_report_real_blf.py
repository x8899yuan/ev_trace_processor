from pathlib import Path

from readers.blf_reader import BlfReader
from services.blf_inventory_report_service import BlfInventoryReportService
from services.blf_inventory_service import BlfInventoryService


BLF_FILE = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")


def test_real_blf_report() -> None:
    trace = BlfReader().read(BLF_FILE)
    inventory = BlfInventoryService().analyze(trace)
    report_service = BlfInventoryReportService()
    report = report_service.generate_report(inventory)

    print()
    print(report)

    assert "BLF Inventory Report" in report
    assert "Total Frames:" in report
    assert "Unique CAN IDs:" in report
    assert "Top CAN IDs" in report

    report_path = report_service.save_report(inventory, BLF_FILE.name)

    assert report_path.exists()
    assert report_path.is_file()
    assert report_path.suffix == ".txt"
    assert report_path.parent.name == "blf"
    assert report_path.name == "blf_inventory.txt"
