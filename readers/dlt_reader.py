import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Optional

from pydlt.header import StandardHeader, StorageHeader
from pydlt.message import DltMessage

from models.processed_trace import ProcessedTrace
from models.trace_event import TraceEvent
from models.trace_metadata import TraceMetadata
from readers.base_reader import BaseReader


class DltReader(BaseReader):
    SUPPORTED_EXTENSION = ".dlt"
    STORAGE_PATTERN = b"DLT\x01"
    SEARCH_CHUNK_SIZE = 65536

    def __init__(self, max_events: Optional[int] = None) -> None:
        if max_events is not None and max_events < 1:
            raise ValueError("max_events must be greater than zero")

        self.max_events = max_events
        self.last_read_stats: dict[str, int] = {}

    def supports(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == self.SUPPORTED_EXTENSION

    def read(self, file_path: Path) -> ProcessedTrace:
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"DLT file not found: {file_path}")

        if not file_path.is_file():
            raise ValueError(f"DLT path is not a file: {file_path}")

        if not self.supports(file_path):
            raise ValueError(f"Unsupported DLT file extension: {file_path.suffix}")

        events: list[TraceEvent] = []
        decoded_records = 0
        skipped_records = 0
        resynchronizations = 0

        with file_path.open("rb") as stream:
            while self.max_events is None or len(events) < self.max_events:
                record, resynchronized = self._read_record(stream)

                if record is None:
                    break

                if resynchronized:
                    resynchronizations += 1

                try:
                    message = DltMessage.create_from_bytes(record, True)
                except (ValueError, struct.error, UnicodeError):
                    skipped_records += 1
                    continue

                events.append(self._to_event(message))
                decoded_records += 1

        start_timestamp = events[0].timestamp if events else None
        end_timestamp = events[-1].timestamp if events else None

        metadata = TraceMetadata(
            file_path=file_path,
            trace_type="DLT",
            file_size_bytes=file_path.stat().st_size,
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
            event_count=len(events),
        )

        self.last_read_stats = {
            "decoded_records": decoded_records,
            "skipped_records": skipped_records,
            "resynchronizations": resynchronizations,
            "event_count": len(events),
        }

        return ProcessedTrace(metadata=metadata, events=events)

    def _read_record(self, stream: BinaryIO) -> tuple[Optional[bytes], bool]:
        resynchronized = self._position_at_storage_pattern(stream)

        if resynchronized is None:
            return None, False

        record_start = stream.tell()
        min_length = StorageHeader.DATA_LENGTH + StandardHeader.DATA_MIN_LENGTH
        header = stream.read(min_length)

        if len(header) < min_length:
            return None, bool(resynchronized)

        try:
            length = struct.unpack_from(
                StandardHeader.STRUCT_MIN_FORMAT,
                header,
                StorageHeader.DATA_LENGTH,
            )[2]
        except struct.error:
            stream.seek(record_start + 1)
            return self._read_record(stream)

        record_length = StorageHeader.DATA_LENGTH + length

        if record_length < min_length:
            stream.seek(record_start + 1)
            return self._read_record(stream)

        remainder = stream.read(record_length - min_length)

        if len(remainder) < record_length - min_length:
            return None, bool(resynchronized)

        return header + remainder, bool(resynchronized)

    def _position_at_storage_pattern(
        self,
        stream: BinaryIO,
    ) -> Optional[bool]:
        start = stream.tell()
        marker = stream.read(len(self.STORAGE_PATTERN))

        if not marker:
            return None

        if marker == self.STORAGE_PATTERN:
            stream.seek(start)
            return False

        stream.seek(start)
        overlap = b""

        while True:
            chunk_start = stream.tell()
            chunk = stream.read(self.SEARCH_CHUNK_SIZE)

            if not chunk:
                return None

            data = overlap + chunk
            index = data.find(self.STORAGE_PATTERN)

            if index >= 0:
                marker_position = (
                    chunk_start - len(overlap) + index
                )
                stream.seek(marker_position)
                return True

            overlap = data[-(len(self.STORAGE_PATTERN) - 1):]

    def _to_event(self, message: DltMessage) -> TraceEvent:
        timestamp = self._get_timestamp(message)
        std_header = getattr(message, "std_header", None)
        ext_header = getattr(message, "ext_header", None)
        payload = getattr(message, "payload", None)
        application_id = getattr(ext_header, "application_id", None)
        context_id = getattr(ext_header, "context_id", None)
        event_name = ".".join(
            value for value in (application_id, context_id) if value
        ) or "DLT"

        event_payload: dict[str, Any] = {
            "ecu_id": self._get_ecu_id(message),
            "application_id": application_id,
            "context_id": context_id,
            "message_counter": getattr(std_header, "message_counter", None),
            "message_length": getattr(std_header, "length", None),
            "dlt_timestamp": getattr(std_header, "timestamp", None),
            "verbose": getattr(ext_header, "verbose", None),
            "message_type": getattr(ext_header, "message_type", None),
            "message_type_info": getattr(
                ext_header,
                "message_type_info",
                None,
            ),
            "number_of_arguments": getattr(
                ext_header,
                "number_of_arguments",
                None,
            ),
            "message": str(message),
        }

        arguments = getattr(payload, "arguments", None)

        if arguments is not None:
            event_payload["arguments"] = [
                {
                    "type": type(argument).__name__,
                    "value": self._normalize_value(
                        getattr(argument, "data", str(argument))
                    ),
                }
                for argument in arguments
            ]

        message_id = getattr(payload, "message_id", None)

        if message_id is not None:
            event_payload["message_id"] = message_id

        non_static_data = getattr(payload, "non_static_data", None)

        if non_static_data is not None:
            event_payload["non_static_data_hex"] = bytes(
                non_static_data
            ).hex()

        return TraceEvent(
            timestamp=timestamp,
            source_type="DLT",
            event_name=event_name,
            payload=event_payload,
        )

    def _get_timestamp(self, message: DltMessage) -> datetime:
        str_header = getattr(message, "str_header", None)
        seconds = getattr(str_header, "seconds", 0)
        microseconds = getattr(str_header, "microseconds", 0)

        return datetime.fromtimestamp(
            seconds + microseconds / 1_000_000,
            tz=timezone.utc,
        )

    def _get_ecu_id(self, message: DltMessage) -> Optional[str]:
        str_header = getattr(message, "str_header", None)
        std_header = getattr(message, "std_header", None)

        return (
            getattr(str_header, "ecu_id", None)
            or getattr(std_header, "ecu_id", None)
        )

    def _normalize_value(self, value: Any) -> Any:
        if isinstance(value, bytes):
            return value.hex()

        if isinstance(value, (str, int, float, bool)) or value is None:
            return value

        if isinstance(value, list):
            return [self._normalize_value(item) for item in value]

        if isinstance(value, tuple):
            return [self._normalize_value(item) for item in value]

        if isinstance(value, dict):
            return {
                str(key): self._normalize_value(item)
                for key, item in value.items()
            }

        return str(value)
