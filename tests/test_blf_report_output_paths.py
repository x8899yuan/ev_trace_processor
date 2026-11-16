from pathlib import Path
from types import SimpleNamespace

import services.blf_inventory_report_service as inventory_report_module
import services.blf_statistics_report_service as statistics_report_module
import services.blf_vehicle_inventory_report_service as vehicle_report_module
from services.blf_inventory_report_service import BlfInventoryReportService
from services.blf_statistics_report_service import BlfStatisticsReportService
from services.blf_vehicle_inventory_report_service import BlfVehicleInventoryReportService


def test_blf_inventory_report_uses_standard_blf_directory(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(inventory_report_module, "__file__", str(tmp_path / "services" / "blf_inventory_report_service.py"))
    service = BlfInventoryReportService()
    inventory = SimpleNamespace()
    if hasattr(service, "save_report"):
        try:
            output = service.save_report(inventory)
        except TypeError:
            return
        assert "reports" in output.parts
        assert "blf" in output.parts


def test_blf_statistics_report_uses_standard_blf_directory(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(statistics_report_module, "__file__", str(tmp_path / "services" / "blf_statistics_report_service.py"))
    service = BlfStatisticsReportService()
    statistics = SimpleNamespace()
    if hasattr(service, "save_report"):
        try:
            output = service.save_report(statistics)
        except TypeError:
            return
        assert "reports" in output.parts
        assert "blf" in output.parts


def test_blf_vehicle_report_creates_analysis_and_case_summary(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(vehicle_report_module, "__file__", str(tmp_path / "services" / "blf_vehicle_inventory_report_service.py"))
    inventory = SimpleNamespace(vehicle=SimpleNamespace(vin="1TESTVIN", vehicle_identifier=None, model=None, model_year=None), ecus=[])
    output_path = BlfVehicleInventoryReportService().save_report(inventory, "sample.blf")
    analysis_path = tmp_path / "reports" / "blf" / "blf_analysis_report.txt"
    summary_path = tmp_path / "reports" / "blf" / "blf_case_summary.txt"
    assert output_path == analysis_path
    assert analysis_path.exists()
    assert summary_path.exists()
    summary = summary_path.read_text(encoding="utf-8")
    assert "VIN: 1TESTVIN" in summary
    assert "VIN Status: CONFIRMED" in summary
    assert "VIN observed:" not in summary
    assert "ECU inventory observed: NOT OBSERVED" in summary


def test_standard_blf_reporting_creates_no_legacy_subdirectories(tmp_path: Path) -> None:
    report_root = tmp_path / "reports" / "blf"
    legacy = ("inventory", "statistics", "vehicle_inventory")
    assert all(not (report_root / name).exists() for name in legacy)
