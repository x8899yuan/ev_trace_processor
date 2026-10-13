from pathlib import Path

from models.decoded_can_message import DecodedCanMessage
from services.dbc_service import DbcService


class DbcDecoderService:
    def __init__(
        self,
        dbc_service: DbcService | None = None,
    ) -> None:
        self._dbc_service = (
            dbc_service
            if dbc_service is not None
            else DbcService()
        )
        self._database_cache: dict[str, object] = {}

    def _get_database(self, dbc_file: Path):
        dbc_file = Path(dbc_file)
        cache_key = str(dbc_file.resolve())

        if cache_key not in self._database_cache:
            self._database_cache[cache_key] = self._dbc_service.load(
                dbc_file
            )

        return self._database_cache[cache_key]

    def decode_message(
        self,
        dbc_file: Path,
        arbitration_id: int,
        data: bytes,
    ) -> dict:
        database = self._get_database(dbc_file)
        message = database.get_message_by_frame_id(arbitration_id)
        return message.decode(data)

    def decode_can_message(
        self,
        dbc_file: Path,
        timestamp: float,
        channel: int,
        arbitration_id: int,
        data: bytes,
    ) -> DecodedCanMessage:
        database = self._get_database(dbc_file)
        message = database.get_message_by_frame_id(arbitration_id)
        signals = message.decode(data)

        return DecodedCanMessage(
            timestamp=timestamp,
            channel=channel,
            can_id=arbitration_id,
            message_name=message.name,
            dlc=len(data),
            signals=signals,
        )

    def message_exists(
        self,
        dbc_file: Path,
        arbitration_id: int,
    ) -> bool:
        database = self._get_database(dbc_file)

        try:
            database.get_message_by_frame_id(arbitration_id)
            return True
        except KeyError:
            return False

    def message_name(
        self,
        dbc_file: Path,
        arbitration_id: int,
    ) -> str | None:
        database = self._get_database(dbc_file)

        try:
            message = database.get_message_by_frame_id(arbitration_id)
            return message.name
        except KeyError:
            return None
