import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Optional

from models.processed_trace import ProcessedTrace
from models.vehicle_software_inventory import (
    EcuSoftwareInfo,
    EvidenceItem,
    VehicleSoftwareInventory,
)


class DltVehicleSoftwareInventoryExtractor:
    VIN_PATTERN = re.compile(r"(?<![A-HJ-NPR-Z0-9])[A-HJ-NPR-Z0-9]{17}(?![A-HJ-NPR-Z0-9])")

    FIELD_PATTERNS = {
        "software_version": (
            re.compile(r"\b(?:software|sw)\s*(?:version|ver\.?|release)\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
            re.compile(r"\bversion\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
        ),
        "software_part_number": (
            re.compile(r"\b(?:software|sw)\s*(?:part\s*(?:number|no\.?|nr\.?))\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
            re.compile(r"\b(?:swpn|sw_pn)\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
        ),
        "hardware_part_number": (
            re.compile(r"\b(?:hardware|hw)\s*(?:part\s*(?:number|no\.?|nr\.?))\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
            re.compile(r"\b(?:hwpn|hw_pn)\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
        ),
        "hardware_version": (
            re.compile(r"\b(?:hardware|hw)\s*(?:version|ver\.?)\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
        ),
        "bootloader_version": (
            re.compile(r"\bboot(?:loader)?\s*(?:version|ver\.?)\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
        ),
        "dataset_version": (
            re.compile(r"\b(?:dataset|data\s*set)\s*(?:version|ver\.?)\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
        ),
        "build_id": (
            re.compile(r"\b(?:build\s*(?:id|number|no\.?|nr\.?)|build)\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
        ),
        "revision": (
            re.compile(r"\b(?:revision|rev\.?)\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
        ),
        "software_name": (
            re.compile(r"\b(?:software|sw)\s*(?:name|component)\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
        ),
    }

    VEHICLE_PATTERNS = {
        "vehicle_identifier": (
            re.compile(r"\bvehicle\s*(?:id|identifier)\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
        ),
        "model": (
            re.compile(r"\bvehicle\s*model\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
            re.compile(r"\bmodel\s*[:=]\s*([^,;|]+)", re.IGNORECASE),
        ),
        "model_year": (
            re.compile(r"\bmodel\s*year\s*[:=]\s*((?:19|20)\d{2})\b", re.IGNORECASE),
        ),
    }

    COMPONENT_BY_FILENAME = {
        "adaptivevm": "AdaptiveVM",
        "housekeepingvm": "HousekeepingVM",
        "javavm": "JavaVM",
        "r7": "R7",
    }

    def extract(
        self,
        traces: ProcessedTrace | Iterable[ProcessedTrace],
    ) -> VehicleSoftwareInventory:
        trace_list = self._normalize_traces(traces)
        inventory = VehicleSoftwareInventory()
        ecu_by_id: dict[str, EcuSoftwareInfo] = {}
        candidates = defaultdict(list)

        for trace in trace_list:
            component_name = self._component_name(trace.metadata.file_name)

            for event in trace.events:
                payload = event.payload
                ecu_id = payload.get("ecu_id")

                if ecu_id and ecu_id not in ecu_by_id:
                    ecu = EcuSoftwareInfo(
                        component_name=component_name,
                        ecu_id=str(ecu_id),
                    )
                    ecu_by_id[str(ecu_id)] = ecu
                    inventory.ecus.append(ecu)

                message = self._message_content(payload)

                if not message:
                    continue

                evidence_context = {
                    "source_file": trace.metadata.file_name,
                    "timestamp": event.timestamp.isoformat(),
                    "application_id": payload.get("application_id"),
                    "context_id": payload.get("context_id"),
                    "message": message,
                }

                self._extract_vehicle_identity(
                    message,
                    evidence_context,
                    inventory,
                    candidates,
                )

                if ecu_id:
                    self._extract_ecu_software(
                        message,
                        evidence_context,
                        ecu_by_id[str(ecu_id)],
                        candidates,
                    )

        self._select_vehicle_values(inventory, candidates)
        self._select_ecu_values(inventory, candidates)
        inventory.ecus.sort(key=lambda ecu: (ecu.component_name, ecu.ecu_id))
        return inventory

    def _normalize_traces(
        self,
        traces: ProcessedTrace | Iterable[ProcessedTrace],
    ) -> list[ProcessedTrace]:
        if isinstance(traces, ProcessedTrace):
            trace_list = [traces]
        else:
            trace_list = list(traces)

        if not trace_list:
            raise ValueError("At least one DLT trace is required")

        for trace in trace_list:
            if trace.metadata.trace_type != "DLT":
                raise ValueError(
                    "DltVehicleSoftwareInventoryExtractor requires DLT traces"
                )

        return trace_list

    def _component_name(self, file_name: str) -> str:
        lowered = file_name.lower()

        for token, component_name in self.COMPONENT_BY_FILENAME.items():
            if token in lowered:
                return component_name

        return Path(file_name).stem

    def _message_content(self, payload: dict) -> str:
        arguments = payload.get("arguments", [])

        if arguments:
            return " ".join(
                str(argument.get("value", ""))
                for argument in arguments
            ).strip()

        return str(payload.get("message", "")).strip()

    def _extract_vehicle_identity(
        self,
        message: str,
        context: dict,
        inventory: VehicleSoftwareInventory,
        candidates: dict,
    ) -> None:
        lowered = message.lower()

        if "vin" in lowered or "vehicle identification" in lowered:
            for vin in self.VIN_PATTERN.findall(message.upper()):
                evidence = self._evidence(vin, context)
                candidates[("vehicle", "vin")].append(evidence)

        for field_name, patterns in self.VEHICLE_PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(message)
                if match:
                    value = self._clean_value(match.group(1))
                    if value:
                        candidates[("vehicle", field_name)].append(
                            self._evidence(value, context)
                        )
                    break

    def _extract_ecu_software(
        self,
        message: str,
        context: dict,
        ecu: EcuSoftwareInfo,
        candidates: dict,
    ) -> None:
        for field_name, patterns in self.FIELD_PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(message)
                if match:
                    value = self._clean_value(match.group(1))
                    if value:
                        evidence = self._evidence(value, context)
                        candidates[("ecu", ecu.ecu_id, field_name)].append(evidence)
                    break

    def _select_vehicle_values(
        self,
        inventory: VehicleSoftwareInventory,
        candidates: dict,
    ) -> None:
        for field_name in ("vin", "vehicle_identifier", "model", "model_year"):
            evidence_items = candidates.get(("vehicle", field_name), [])
            selected = self._select_consistent_value(evidence_items)

            if selected is not None:
                setattr(inventory, field_name, selected.value)
                inventory.vehicle_evidence.extend(
                    item for item in evidence_items if item.value == selected.value
                )

    def _select_ecu_values(
        self,
        inventory: VehicleSoftwareInventory,
        candidates: dict,
    ) -> None:
        fields = (
            "software_name",
            "software_version",
            "software_part_number",
            "hardware_part_number",
            "hardware_version",
            "bootloader_version",
            "dataset_version",
            "build_id",
            "revision",
        )

        for ecu in inventory.ecus:
            for field_name in fields:
                evidence_items = candidates.get(("ecu", ecu.ecu_id, field_name), [])
                selected = self._select_consistent_value(evidence_items)

                if selected is not None:
                    setattr(ecu, field_name, selected.value)
                    ecu.evidence.extend(
                        item for item in evidence_items if item.value == selected.value
                    )

    def _select_consistent_value(
        self,
        evidence_items: list[EvidenceItem],
    ) -> Optional[EvidenceItem]:
        if not evidence_items:
            return None

        counts = defaultdict(int)

        for item in evidence_items:
            counts[item.value] += 1

        max_count = max(counts.values())
        winners = sorted(
            value for value, count in counts.items() if count == max_count
        )

        if len(winners) != 1:
            return None

        winning_value = winners[0]
        return next(item for item in evidence_items if item.value == winning_value)

    def _evidence(self, value: str, context: dict) -> EvidenceItem:
        return EvidenceItem(
            value=value,
            source_file=context["source_file"],
            timestamp=context["timestamp"],
            application_id=context["application_id"],
            context_id=context["context_id"],
            message=context["message"],
        )

    def _clean_value(self, value: str) -> str:
        value = value.strip().strip('"\'')
        value = re.sub(r"\s+", " ", value)
        return value[:200].strip()
