from dataclasses import dataclass, field
from typing import Optional


@dataclass(slots=True)
class InventoryEvidence:
    value: str
    source_type: str
    source_file: str
    timestamp: Optional[str] = None
    ecu_id: Optional[str] = None
    application_id: Optional[str] = None
    context_id: Optional[str] = None
    message: Optional[str] = None
    verification_status: str = "observed"

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "source_type": self.source_type,
            "source_file": self.source_file,
            "timestamp": self.timestamp,
            "ecu_id": self.ecu_id,
            "application_id": self.application_id,
            "context_id": self.context_id,
            "message": self.message,
            "verification_status": self.verification_status,
        }


@dataclass(slots=True)
class SoftwareComponentInfo:
    name: str
    version: Optional[str] = None
    release: Optional[str] = None
    profile: Optional[str] = None
    build: Optional[str] = None
    hash_value: Optional[str] = None
    evidence: list[InventoryEvidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "release": self.release,
            "profile": self.profile,
            "build": self.build,
            "hash_value": self.hash_value,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(slots=True)
class SoftwareClusterInfo:
    name: str
    version: Optional[str] = None
    evidence: list[InventoryEvidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(slots=True)
class EcuInventoryInfo:
    name: Optional[str] = None
    ecu_id: Optional[str] = None
    hardware_part_number: Optional[str] = None
    hardware_version: Optional[str] = None
    software_part_number: Optional[str] = None
    platform_version: Optional[str] = None
    bootloader_version: Optional[str] = None
    dataset_version: Optional[str] = None
    evidence: list[InventoryEvidence] = field(default_factory=list)
    software_clusters: list[SoftwareClusterInfo] = field(default_factory=list)
    software_components: list[SoftwareComponentInfo] = field(default_factory=list)

    def get_cluster(self, name: str) -> Optional[SoftwareClusterInfo]:
        return next((item for item in self.software_clusters if item.name == name), None)

    def get_component(self, name: str) -> Optional[SoftwareComponentInfo]:
        return next((item for item in self.software_components if item.name == name), None)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ecu_id": self.ecu_id,
            "hardware_part_number": self.hardware_part_number,
            "hardware_version": self.hardware_version,
            "software_part_number": self.software_part_number,
            "platform_version": self.platform_version,
            "bootloader_version": self.bootloader_version,
            "dataset_version": self.dataset_version,
            "evidence": [item.to_dict() for item in self.evidence],
            "software_clusters": [item.to_dict() for item in self.software_clusters],
            "software_components": [item.to_dict() for item in self.software_components],
        }


@dataclass(slots=True)
class VehicleIdentityInfo:
    vin: Optional[str] = None
    vehicle_identifier: Optional[str] = None
    model: Optional[str] = None
    model_year: Optional[str] = None
    evidence: list[InventoryEvidence] = field(default_factory=list)

    @property
    def identified(self) -> bool:
        return bool(self.vin or self.vehicle_identifier or self.model or self.model_year)

    def to_dict(self) -> dict:
        return {
            "vin": self.vin,
            "vehicle_identifier": self.vehicle_identifier,
            "model": self.model,
            "model_year": self.model_year,
            "identified": self.identified,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(slots=True)
class VehicleSoftwareInventory:
    vehicle: VehicleIdentityInfo = field(default_factory=VehicleIdentityInfo)
    ecus: list[EcuInventoryInfo] = field(default_factory=list)

    def get_ecu(self, ecu_id: str) -> Optional[EcuInventoryInfo]:
        return next((item for item in self.ecus if item.ecu_id == ecu_id), None)

    def to_dict(self) -> dict:
        return {
            "vehicle": self.vehicle.to_dict(),
            "ecus": [item.to_dict() for item in self.ecus],
        }
