import re
from typing import Iterable

from models.processed_trace import ProcessedTrace
from models.vehicle_software_inventory import (
    EcuInventoryInfo,
    InventoryEvidence,
    SoftwareClusterInfo,
    SoftwareComponentInfo,
    VehicleSoftwareInventory,
)


class DltSoftwareInventoryExtractor:
    COMPONENT_BY_FILENAME = {
        "adaptivevm": "AdaptiveVM",
        "housekeepingvm": "HousekeepingVM",
        "javavm": "JavaVM",
        "r7": "R7",
    }

    CLUSTER_PATTERN = re.compile(
        r"Cluster\s+name:\s*([^;]+?)\s*;\s*Cluster\s+version:\s*([0-9]+(?:\.[0-9]+)+)",
        re.IGNORECASE,
    )
    HEARTBEAT_PATTERN = re.compile(
        r"\bApp\s+(.+?)\s+heartbeat\s+Ver:([^\s]+)\s+Rel:([^\s]+)\s+PRL:([^\s]+)\s+Build:([^\s]+)\s+Hash:([^\s]+)",
        re.IGNORECASE,
    )
    R7_VERSION_PATTERN = re.compile(
        r"\bR7\s+sw\s+version:\s*(.*)",
        re.IGNORECASE,
    )

    def extract(
        self,
        traces: ProcessedTrace | Iterable[ProcessedTrace],
    ) -> VehicleSoftwareInventory:
        trace_list = self._normalize_traces(traces)
        inventory = VehicleSoftwareInventory()

        for trace in trace_list:
            ecu = self._ensure_ecu(inventory, trace)

            for event in trace.events:
                payload = event.payload
                message = self._message_content(payload)

                if not message:
                    continue

                evidence_context = {
                    "source_file": trace.metadata.file_name,
                    "timestamp": event.timestamp.isoformat(),
                    "ecu_id": payload.get("ecu_id"),
                    "application_id": payload.get("application_id"),
                    "context_id": payload.get("context_id"),
                    "message": message,
                }

                self._extract_cluster(message, evidence_context, ecu)
                self._extract_component(message, evidence_context, ecu)
                self._extract_r7_version(message, evidence_context, ecu)

        self._finalize(inventory)
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
                raise ValueError("DltSoftwareInventoryExtractor requires DLT traces")

        return trace_list

    def _ensure_ecu(
        self,
        inventory: VehicleSoftwareInventory,
        trace: ProcessedTrace,
    ) -> EcuInventoryInfo:
        ecu_id = self._trace_ecu_id(trace)
        existing = inventory.get_ecu(ecu_id) if ecu_id else None

        if existing is not None:
            return existing

        ecu = EcuInventoryInfo(
            name=self._component_name(trace.metadata.file_name),
            ecu_id=ecu_id,
        )
        inventory.ecus.append(ecu)
        return ecu

    def _trace_ecu_id(self, trace: ProcessedTrace) -> str | None:
        for event in trace.events:
            ecu_id = event.payload.get("ecu_id")
            if ecu_id:
                return str(ecu_id)
        return None

    def _component_name(self, file_name: str) -> str:
        lowered = file_name.lower()
        for token, component_name in self.COMPONENT_BY_FILENAME.items():
            if token in lowered:
                return component_name
        return file_name

    def _message_content(self, payload: dict) -> str:
        arguments = payload.get("arguments", [])
        if arguments:
            return " ".join(
                str(argument.get("value", ""))
                for argument in arguments
            ).strip()
        return str(payload.get("message", "")).strip()

    def _extract_cluster(
        self,
        message: str,
        context: dict,
        ecu: EcuInventoryInfo,
    ) -> None:
        match = self.CLUSTER_PATTERN.search(message)
        if not match:
            return

        name = self._clean(match.group(1))
        version = self._clean(match.group(2))
        if not name or not version:
            return

        cluster = ecu.get_cluster(name)
        if cluster is None:
            cluster = SoftwareClusterInfo(name=name)
            ecu.software_clusters.append(cluster)

        evidence = self._evidence(version, context)
        cluster.evidence.append(evidence)

        if cluster.version is None:
            cluster.version = version
        elif cluster.version != version:
            cluster.version = None

    def _extract_component(
        self,
        message: str,
        context: dict,
        ecu: EcuInventoryInfo,
    ) -> None:
        match = self.HEARTBEAT_PATTERN.search(message)
        if not match:
            return

        name = self._clean(match.group(1))
        version = self._usable(match.group(2))
        release = self._usable(match.group(3))
        profile = self._usable(match.group(4))
        build = self._usable(match.group(5))
        hash_value = self._usable(match.group(6))

        if not name:
            return

        component = ecu.get_component(name)
        if component is None:
            component = SoftwareComponentInfo(name=name)
            ecu.software_components.append(component)

        self._merge_component_value(component, "version", version)
        self._merge_component_value(component, "release", release)
        self._merge_component_value(component, "profile", profile)
        self._merge_component_value(component, "build", build)
        self._merge_component_value(component, "hash_value", hash_value)

        evidence_value = version or name
        component.evidence.append(self._evidence(evidence_value, context))

    def _extract_r7_version(
        self,
        message: str,
        context: dict,
        ecu: EcuInventoryInfo,
    ) -> None:
        if ecu.name != "R7":
            return

        match = self.R7_VERSION_PATTERN.search(message)
        if not match:
            return

        value = self._clean_binary_text(match.group(1))
        if not value:
            return

        evidence = self._evidence(value, context)
        ecu.evidence.append(evidence)

        if ecu.platform_version is None:
            ecu.platform_version = value
        elif ecu.platform_version != value:
            ecu.platform_version = None

    def _merge_component_value(
        self,
        component: SoftwareComponentInfo,
        field_name: str,
        value: str | None,
    ) -> None:
        if value is None:
            return

        existing = getattr(component, field_name)
        if existing is None:
            setattr(component, field_name, value)
        elif existing != value:
            setattr(component, field_name, None)

    def _finalize(self, inventory: VehicleSoftwareInventory) -> None:
        for ecu in inventory.ecus:
            versions = {
                cluster.version
                for cluster in ecu.software_clusters
                if cluster.version
            }
            if len(versions) == 1 and ecu.platform_version is None:
                ecu.platform_version = next(iter(versions))

            ecu.software_clusters.sort(key=lambda item: item.name.lower())
            ecu.software_components.sort(key=lambda item: item.name.lower())

        inventory.ecus.sort(key=lambda item: ((item.name or "").lower(), item.ecu_id or ""))

    def _evidence(self, value: str, context: dict) -> InventoryEvidence:
        return InventoryEvidence(
            value=value,
            source_type="DLT",
            source_file=context["source_file"],
            timestamp=context["timestamp"],
            ecu_id=context["ecu_id"],
            application_id=context["application_id"],
            context_id=context["context_id"],
            message=context["message"],
            verification_status="observed",
        )

    def _usable(self, value: str) -> str | None:
        cleaned = self._clean(value)
        if not cleaned or cleaned.lower() in {"n/a", "na", "none", "unknown", "-"}:
            return None
        return cleaned

    def _clean(self, value: str) -> str:
        value = value.replace("\x00", " ")
        value = re.sub(r"\s+", " ", value)
        return value.strip().strip('"\'').strip()

    def _clean_binary_text(self, value: str) -> str | None:
        cleaned = self._clean(value)
        tokens = re.findall(r"[A-Za-z0-9._-]{4,}", cleaned)
        if not tokens:
            return None
        return max(tokens, key=len)
