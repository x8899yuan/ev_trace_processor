from pathlib import Path

import pytest

from readers.dlt_reader import DltReader
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
def inventory():
    traces = [
        DltReader(max_events=SAMPLE_SIZE).read(path)
        for path in get_real_dlt_files()
    ]
    return DltSoftwareInventoryExtractor().extract(traces)


def test_real_dlt_inventory_does_not_guess_vehicle_identity(inventory):
    assert inventory.vehicle.vin is None
    assert inventory.vehicle.vehicle_identifier is None
    assert inventory.vehicle.model is None
    assert inventory.vehicle.model_year is None
    assert inventory.vehicle.identified is False


def test_real_dlt_inventory_contains_four_icas1_components(inventory):
    assert {(ecu.name, ecu.ecu_id) for ecu in inventory.ecus} == {
        ("AdaptiveVM", "8123"),
        ("HousekeepingVM", "C003"),
        ("JavaVM", "8124"),
        ("R7", "C002"),
    }


def test_real_dlt_adaptive_vm_platform_version(inventory):
    ecu = inventory.get_ecu("8123")
    assert ecu is not None
    assert ecu.name == "AdaptiveVM"
    assert ecu.platform_version == "1.660.0"
    assert ecu.get_cluster("AdaptiveCore").version == "1.660.0"
    assert ecu.get_cluster("ServiceChargeManagementCore").version == "1.660.0"
    assert ecu.get_cluster("ECU_Diagnosis").version == "1.660.0"


def test_real_dlt_housekeeping_vm_platform_version(inventory):
    ecu = inventory.get_ecu("C003")
    assert ecu is not None
    assert ecu.name == "HousekeepingVM"
    assert ecu.platform_version == "1.660.0"
    assert ecu.get_cluster("FirmwareAP").version == "1.660.0"
    assert ecu.get_cluster("HypervisorLinuxKernel").version == "1.660.0"
    assert ecu.get_cluster("TrustZone").version == "1.660.0"


def test_real_dlt_r7_software_identifier_is_cleaned(inventory):
    ecu = inventory.get_ecu("C002")
    assert ecu is not None
    assert ecu.name == "R7"
    assert ecu.platform_version == "0657002611CAIP"
    assert "\x00" not in ecu.platform_version
    assert ecu.evidence
    assert all(item.source_type == "DLT" for item in ecu.evidence)


def test_real_dlt_java_vm_does_not_accept_generic_service_version(inventory):
    ecu = inventory.get_ecu("8124")
    assert ecu is not None
    assert ecu.name == "JavaVM"
    assert ecu.platform_version is None
    assert "12 Local:" not in str(ecu.to_dict())


def test_real_dlt_alias_manager_heartbeat_version(inventory):
    ecu = inventory.get_ecu("8123")
    component = ecu.get_component("alias-manager")
    assert component is not None
    assert component.version == "4.4.14.100105"
    assert component.release is None
    assert component.profile == "DEV_4CPX"
    assert component.build == "Release"
    assert component.hash_value is None


def test_real_dlt_manifest_manager_heartbeat_version(inventory):
    ecu = inventory.get_ecu("8123")
    component = ecu.get_component("manifest-manage")
    assert component is not None
    assert component.version == "5.7.0.100206"
    assert component.release is None
    assert component.profile == "DEV_4CPX"
    assert component.build == "Release"
    assert component.hash_value is None


def test_real_dlt_rejects_na_metadata(inventory):
    for ecu in inventory.ecus:
        for component in ecu.software_components:
            values = {
                component.release,
                component.profile,
                component.build,
                component.hash_value,
            }
            assert "n/a" not in values


def test_real_dlt_cluster_values_are_trimmed(inventory):
    for ecu_id in ("8123", "C003"):
        ecu = inventory.get_ecu(ecu_id)
        assert ecu is not None
        for cluster in ecu.software_clusters:
            assert cluster.version == "1.660.0"
            assert "following executable" not in cluster.version


def test_real_dlt_inventory_evidence_has_provenance(inventory):
    ecu = inventory.get_ecu("8123")
    cluster = ecu.get_cluster("AdaptiveCore")
    assert cluster is not None
    assert cluster.evidence
    evidence = cluster.evidence[0]
    assert evidence.source_type == "DLT"
    assert evidence.source_file == DLT_FILES[0]
    assert evidence.ecu_id == "8123"
    assert evidence.application_id == "Apav"
    assert evidence.context_id == "DFLT"
    assert evidence.timestamp is not None
    assert "Cluster name:" in evidence.message


def test_real_dlt_inventory_serializes(inventory):
    data = inventory.to_dict()
    assert data["vehicle"]["vin"] is None
    assert data["vehicle"]["identified"] is False
    assert len(data["ecus"]) == 4
    assert any(item["ecu_id"] == "C002" for item in data["ecus"])
