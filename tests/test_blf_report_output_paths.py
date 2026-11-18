from pathlib import Path
from types import SimpleNamespace

import services.blf_vehicle_inventory_report_service as vehicle_report_module
from services.blf_vehicle_inventory_report_service import BlfVehicleInventoryReportService


def test_blf_vehicle_report_creates_standard_analysis_and_case_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(vehicle_report_module, "__file__", str(tmp_path / "services" / "blf_vehicle_inventory_report_service.py"))
    inventory = SimpleNamespace(vehicle=SimpleNamespace(vin="1TESTVIN"), ecus=[])
    output = BlfVehicleInventoryReportService().save_report(inventory, "sample.blf")
    analysis = tmp_path / "reports" / "blf" / "blf_analysis_report.txt"
    summary = tmp_path / "reports" / "blf" / "blf_case_summary.txt"
    assert output == analysis
    assert analysis.exists() and summary.exists()
    text = summary.read_text(encoding="utf-8")
    assert "VIN: 1TESTVIN" in text
    assert "VIN Status: CONFIRMED" in text


def test_standard_blf_reporting_creates_no_legacy_subdirectories(tmp_path):
    report_root = tmp_path / "reports" / "blf"
    assert all(not (report_root / name).exists() for name in ("inventory", "statistics", "vehicle_inventory"))
