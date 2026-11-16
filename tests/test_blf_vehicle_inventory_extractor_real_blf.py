from pathlib import Path

from readers.blf_reader import BlfReader
from services.blf_vehicle_inventory_extractor import BlfVehicleInventoryExtractor


BLF_FILE = Path("data/blf/VW31666_0173_20260508_140000h_Trace.blf")
DBC_FILE = Path("dbc/E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")
EXPECTED_VIN = "1V2ZZZE81TC000011"


def test_extract_inventory_from_real_blf() -> None:
    assert BLF_FILE.exists()
    assert DBC_FILE.exists()

    trace = BlfReader().read(BLF_FILE)
    inventory = BlfVehicleInventoryExtractor().extract(trace, DBC_FILE)

    assert trace.event_count > 0
    assert inventory.ecus

    ecu_ids = [ecu.ecu_id for ecu in inventory.ecus]
    assert all(ecu_id for ecu_id in ecu_ids)
    assert len(ecu_ids) == len(set(ecu_ids))

    evidence_count = 0

    for ecu in inventory.ecus:
        assert ecu.name
        assert ecu.ecu_id
        assert ecu.evidence

        for evidence in ecu.evidence:
            evidence_count += 1
            assert evidence.source_type == "BLF"
            assert evidence.source_file.endswith(BLF_FILE.name)
            assert evidence.timestamp
            assert evidence.ecu_id == ecu.ecu_id
            assert evidence.value
            assert evidence.message
            assert "DBC message" in evidence.message
            assert "CAN ID 0x" in evidence.message
            assert evidence.verification_status == "observed"

    assert evidence_count > 0
    assert inventory.vehicle.vin == EXPECTED_VIN
    assert inventory.vehicle.identified
    assert inventory.vehicle.vehicle_identifier is None
    assert inventory.vehicle.model is None
    assert inventory.vehicle.model_year is None
    assert len(inventory.vehicle.evidence) == 1

    vin_evidence = inventory.vehicle.evidence[0]
    assert vin_evidence.value == EXPECTED_VIN
    assert vin_evidence.source_type == "BLF"
    assert vin_evidence.source_file.endswith(BLF_FILE.name)
    assert vin_evidence.timestamp
    assert vin_evidence.ecu_id == "ICAS1_X_Gateway"
    assert vin_evidence.message == (
        "VIN reconstructed from DBC message VIN_01, CAN ID 0x6B4"
    )
    assert vin_evidence.verification_status == "observed"

    for ecu in inventory.ecus:
        assert ecu.hardware_part_number is None
        assert ecu.hardware_version is None
        assert ecu.software_part_number is None
        assert ecu.platform_version is None
        assert ecu.bootloader_version is None
        assert ecu.dataset_version is None
