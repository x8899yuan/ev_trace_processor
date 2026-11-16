from pathlib import Path

import pytest

from readers.dlt_reader import DltReader
from services.dlt_analysis_service import DltAnalysisService
from services.dlt_report_service import DltReportService
from services.dlt_software_inventory_extractor import DltSoftwareInventoryExtractor


DLT_DIRECTORY = Path("data") / "dlt"
SAMPLE_SIZE = 10000

DLT_FILES = [
    "VW31666_0173_20260508_140000h_DLT_ICAS1_AdaptiveVM.dlt",
    "VW31666_0173_20260508_140000h_DLT_ICAS1_HousekeepingVM.dlt",
    "VW31666_0173_20260508_140000h_DLT_ICAS1_JavaVM.dlt",
    "VW31666_0173_20260508_140000h_DLT_ICAS1_R7.dlt",
]


def get_real_dlt_files():
    paths = [DLT_DIRECTORY / name for name in DLT_FILES]
    missing = [path for path in paths if not path.exists()]
    if missing:
        pytest.skip("Real DLT files not available: " + ", ".join(str(path) for path in missing))
    return paths


@pytest.fixture(scope="module")
def pipeline_data():
    traces = [
        DltReader(max_events=SAMPLE_SIZE).read(path)
        for path in get_real_dlt_files()
    ]
    analysis = DltAnalysisService().analyze(traces)
    inventory = DltSoftwareInventoryExtractor().extract(traces)
    return analysis, inventory


@pytest.fixture
def reports(tmp_path, pipeline_data):
    analysis, inventory = pipeline_data
    service = DltReportService(output_directory=tmp_path / "dlt")
    return service.generate(analysis, inventory)


def read_report(path):
    return path.read_text(encoding="utf-8")


def test_inventory_report_renders_vehicle_identity_as_not_identified(reports):
    content = read_report(reports["inventory"])
    assert "Vehicle / software inventory" in content
    assert "VIN: Not identified from DLT" in content
    assert "Vehicle identifier: Not identified from DLT" in content
    assert "Model: Not identified from DLT" in content
    assert "Model year: Not identified from DLT" in content
    assert "CLEUSERMANAGEMENT" not in content


def test_inventory_report_renders_four_icas1_components(reports):
    content = read_report(reports["inventory"])
    assert "AdaptiveVM / ECU 8123" in content
    assert "HousekeepingVM / ECU C003" in content
    assert "JavaVM / ECU 8124" in content
    assert "R7 / ECU C002" in content


def test_inventory_report_renders_platform_versions(reports):
    content = read_report(reports["inventory"])
    assert "AdaptiveVM / ECU 8123\n  Platform/software identifier: 1.660.0" in content
    assert "HousekeepingVM / ECU C003\n  Platform/software identifier: 1.660.0" in content
    assert "JavaVM / ECU 8124\n  Platform/software identifier: Not identified" in content
    assert "R7 / ECU C002\n  Platform/software identifier: 0657002611CAIP" in content
    assert "12 Local:" not in content
    assert "\x00" not in content


def test_inventory_report_renders_known_clusters(reports):
    content = read_report(reports["inventory"])
    assert "Software clusters:" in content
    assert "AdaptiveCore: 1.660.0" in content
    assert "ServiceChargeManagementCore: 1.660.0" in content
    assert "ECU_Diagnosis: 1.660.0" in content
    assert "FirmwareAP: 1.660.0" in content
    assert "HypervisorLinuxKernel: 1.660.0" in content
    assert "TrustZone: 1.660.0" in content


def test_inventory_report_renders_known_application_versions(reports):
    content = read_report(reports["inventory"])
    assert "alias-manager: version=4.4.14.100105, profile=DEV_4CPX, build=Release" in content
    assert "manifest-manage: version=5.7.0.100206, profile=DEV_4CPX, build=Release" in content
    assert "release=n/a" not in content.lower()
    assert "hash=n/a" not in content.lower()


def test_analysis_report_renders_software_inventory(reports):
    content = read_report(reports["analysis"])
    assert "Vehicle / software inventory" in content
    assert "VIN: Not identified from DLT" in content
    assert "AdaptiveVM / ECU 8123" in content
    assert "Platform/software identifier: 1.660.0" in content
    assert "R7 / ECU C002" in content
    assert "Platform/software identifier: 0657002611CAIP" in content


def test_analysis_report_preserves_dlt_findings(reports):
    content = read_report(reports["analysis"])
    assert "FATAL: 1" in content
    assert "ERROR: 2,702" in content
    assert "WARN: 1,017" in content
    assert "Unique normalized finding signatures: 539" in content
    assert "Socket connection to gateway is broken" in content
    assert "R7 RESM.ERR contains reset-related evidence with 155 occurrences" in content


def test_analysis_report_inventory_limitation(reports):
    content = read_report(reports["analysis"])
    assert "only values explicitly observed in the analyzed DLT sample" in content
    assert "does not represent complete vehicle configuration" in content


def test_case_summary_renders_icas1_software_summary(reports):
    content = read_report(reports["case_summary"])
    assert "ICAS1 software summary" in content
    assert "AdaptiveVM / ECU 8123: 1.660.0" in content
    assert "HousekeepingVM / ECU C003: 1.660.0" in content
    assert "JavaVM / ECU 8124: platform version not identified" in content
    assert "R7 / ECU C002: 0657002611CAIP" in content


def test_case_summary_preserves_identity_scope_limitation(reports):
    content = read_report(reports["case_summary"])
    assert "does not by itself establish complete vehicle identity" in content
    assert "complete ECU software inventory" in content
    assert "vehicle-level root cause" in content


def test_report_generation_without_inventory_remains_supported(tmp_path, pipeline_data):
    analysis, _ = pipeline_data
    service = DltReportService(output_directory=tmp_path / "no_inventory")
    reports = service.generate(analysis)
    inventory_content = read_report(reports["inventory"])
    analysis_content = read_report(reports["analysis"])
    assert "Vehicle / software inventory\nNot provided" in inventory_content
    assert "Vehicle / software inventory\nNot provided" in analysis_content


def test_inventory_rendering_does_not_change_event_accounting(reports):
    inventory_content = read_report(reports["inventory"])
    analysis_content = read_report(reports["analysis"])
    case_content = read_report(reports["case_summary"])
    assert "Events analyzed: 40,000" in inventory_content
    assert "Events analyzed: 40,000" in analysis_content
    assert "Events analyzed: 40,000" in case_content
