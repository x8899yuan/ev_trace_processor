from pathlib import Path

from models.processed_trace import ProcessedTrace
from models.vehicle_software_inventory import (
    EcuInventoryInfo,
    InventoryEvidence,
    VehicleSoftwareInventory,
)
from services.dbc_decoder_service import DbcDecoderService


class BlfVehicleInventoryExtractor:
    VIN_MESSAGE_NAME = "VIN_01"
    VIN_POSITION_COUNT = 17

    def __init__(
        self,
        dbc_decoder: DbcDecoderService | None = None,
    ) -> None:
        self._dbc_decoder = (
            dbc_decoder
            if dbc_decoder is not None
            else DbcDecoderService()
        )

    def extract(
        self,
        trace: ProcessedTrace,
        dbc_file: Path,
    ) -> VehicleSoftwareInventory:
        dbc_file = Path(dbc_file)
        inventory = VehicleSoftwareInventory()
        source_file = self._source_file(trace)
        resolution_cache: dict[int, tuple[str | None, list[str]]] = {}
        observed_evidence: set[tuple[str, int, int | None]] = set()
        vin_characters: dict[int, str] = {}
        vin_conflicts: set[int] = set()
        vin_evidence: tuple[str, int, str, str | None] | None = None

        for event in trace.events:
            if event.source_type.upper() != "BLF":
                continue

            if event.event_name != "CAN_FRAME":
                continue

            arbitration_id = event.payload.get("arbitration_id")
            if not isinstance(arbitration_id, int):
                continue

            channel = event.payload.get("channel")

            if arbitration_id not in resolution_cache:
                if not self._dbc_decoder.message_exists(
                    dbc_file,
                    arbitration_id,
                ):
                    resolution_cache[arbitration_id] = (None, [])
                else:
                    resolution_cache[arbitration_id] = (
                        self._dbc_decoder.message_name(
                            dbc_file,
                            arbitration_id,
                        ),
                        self._dbc_decoder.message_senders(
                            dbc_file,
                            arbitration_id,
                        ),
                    )

            message_name, senders = resolution_cache[arbitration_id]

            if message_name is None:
                continue

            timestamp = event.timestamp.isoformat()

            if message_name == self.VIN_MESSAGE_NAME:
                vin_evidence = self._collect_vin_characters(
                    event=event,
                    dbc_file=dbc_file,
                    arbitration_id=arbitration_id,
                    message_name=message_name,
                    senders=senders,
                    characters=vin_characters,
                    conflicts=vin_conflicts,
                    current_evidence=vin_evidence,
                )

            if not senders:
                continue

            for sender in senders:
                if not sender:
                    continue

                evidence_key = (
                    sender,
                    arbitration_id,
                    channel if isinstance(channel, int) else None,
                )

                if evidence_key in observed_evidence:
                    continue

                observed_evidence.add(evidence_key)
                ecu = inventory.get_ecu(sender)

                if ecu is None:
                    ecu = EcuInventoryInfo(
                        name=sender,
                        ecu_id=sender,
                    )
                    inventory.ecus.append(ecu)

                message = self._evidence_message(
                    message_name=message_name,
                    arbitration_id=arbitration_id,
                    channel=channel,
                )

                ecu.evidence.append(
                    InventoryEvidence(
                        value=message_name,
                        source_type="BLF",
                        source_file=source_file,
                        timestamp=timestamp,
                        ecu_id=sender,
                        message=message,
                        verification_status="observed",
                    )
                )

        self._populate_vehicle_vin(
            inventory=inventory,
            source_file=source_file,
            characters=vin_characters,
            conflicts=vin_conflicts,
            vin_evidence=vin_evidence,
        )

        inventory.ecus.sort(
            key=lambda item: (
                item.ecu_id or "",
                item.name or "",
            )
        )

        return inventory

    def _collect_vin_characters(
        self,
        event,
        dbc_file: Path,
        arbitration_id: int,
        message_name: str,
        senders: list[str],
        characters: dict[int, str],
        conflicts: set[int],
        current_evidence: tuple[str, int, str, str | None] | None,
    ) -> tuple[str, int, str, str | None] | None:
        data_hex = event.payload.get("data")

        if not isinstance(data_hex, str):
            return current_evidence

        try:
            decoded = self._dbc_decoder.decode_message(
                dbc_file,
                arbitration_id,
                bytes.fromhex(data_hex),
            )
        except (KeyError, ValueError, TypeError):
            return current_evidence

        found_character = False

        for position in range(1, self.VIN_POSITION_COUNT + 1):
            value = decoded.get(f"VIN_{position}")

            if not isinstance(value, (int, float)):
                continue

            numeric_value = int(value)

            if not 32 <= numeric_value <= 126:
                continue

            character = chr(numeric_value)
            existing = characters.get(position)

            if existing is not None and existing != character:
                conflicts.add(position)
                continue

            characters[position] = character
            found_character = True

        if not found_character or current_evidence is not None:
            return current_evidence

        sender = senders[0] if senders else None

        return (
            event.timestamp.isoformat(),
            arbitration_id,
            message_name,
            sender,
        )

    def _populate_vehicle_vin(
        self,
        inventory: VehicleSoftwareInventory,
        source_file: str,
        characters: dict[int, str],
        conflicts: set[int],
        vin_evidence: tuple[str, int, str, str | None] | None,
    ) -> None:
        if conflicts:
            return

        if len(characters) != self.VIN_POSITION_COUNT:
            return

        vin = "".join(
            characters[position]
            for position in range(1, self.VIN_POSITION_COUNT + 1)
        )

        if len(vin) != self.VIN_POSITION_COUNT:
            return

        inventory.vehicle.vin = vin

        if vin_evidence is None:
            return

        timestamp, arbitration_id, message_name, sender = vin_evidence
        inventory.vehicle.evidence.append(
            InventoryEvidence(
                value=vin,
                source_type="BLF",
                source_file=source_file,
                timestamp=timestamp,
                ecu_id=sender,
                message=(
                    f"VIN reconstructed from DBC message {message_name}, "
                    f"CAN ID 0x{arbitration_id:X}"
                ),
                verification_status="observed",
            )
        )

    def _source_file(
        self,
        trace: ProcessedTrace,
    ) -> str:
        file_path = getattr(trace.metadata, "file_path", None)

        if file_path is None:
            return ""

        return str(file_path)

    def _evidence_message(
        self,
        message_name: str,
        arbitration_id: int,
        channel: object,
    ) -> str:
        can_id = f"0x{arbitration_id:X}"

        if channel is None:
            return f"DBC message {message_name}, CAN ID {can_id}"

        return (
            f"DBC message {message_name}, CAN ID {can_id}, "
            f"channel {channel}"
        )
