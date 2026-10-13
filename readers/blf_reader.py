from pathlib import Path
import can
from models.processed_trace import ProcessedTrace
from models.trace_metadata import TraceMetadata
from readers.base_reader import BaseReader
from datetime import datetime
from models.trace_event import TraceEvent


class BlfReader(BaseReader):
    """
    Reader for BLF trace files.

    Milestone 1 implementation:
    - Validate file extension
    - Validate file existence
    - Create metadata
    - Return empty ProcessedTrace

    Actual BLF parsing will be added later.
    """

    SUPPORTED_EXTENSION = ".blf"

    def supports(self, file_path: Path) -> bool:
        """
        Return True if the file is a BLF trace.
        """
        return (
            file_path.suffix.lower()
            == self.SUPPORTED_EXTENSION
        )

    def read(
        self,
        file_path: Path,
    ) -> ProcessedTrace:

        if not file_path.exists():
            raise FileNotFoundError(
                f"BLF file not found: {file_path}"
            )

        events = self.read_events(
            file_path=file_path,
        )

        start_timestamp = None
        end_timestamp = None

        if events:
            start_timestamp = events[0].timestamp
            end_timestamp = events[-1].timestamp

        metadata = TraceMetadata(
            file_path=file_path,
            trace_type="BLF",
            file_size_bytes=file_path.stat().st_size,
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
            event_count=len(events),
        )

        return ProcessedTrace(
            metadata=metadata,
            events=events,
        )
    
    def get_message_count(
        self,
        file_path: Path,
        ) -> int:
        """
        Return the number of CAN messages
        contained in a BLF file.
        """

        if not file_path.exists():
            raise FileNotFoundError(
            f"BLF file not found: {file_path}"
            )
        count = 0
        with can.BLFReader(str(file_path)) as reader:
            for _ in reader:
                count += 1
        return count
    
    def read_events(
        self,
        file_path: Path,
        max_events: int | None = None,
    ) -> list[TraceEvent]:
        """
        Read CAN messages from a BLF file and convert
       objects.
        """

        if not file_path.exists():
            raise FileNotFoundError(
                f"BLF file not found: {file_path}"
            )

        events: list[TraceEvent] = []

        with can.BLFReader(str(file_path)) as reader:

            for message in reader:

                event = TraceEvent(
                    timestamp=datetime.fromtimestamp(
                        message.timestamp
                    ),
                    source_type="BLF",
                    event_name="CAN_FRAME",
                    payload={
                        "channel": message.channel,
                        "arbitration_id": (
                            message.arbitration_id
                        ),
                        "dlc": message.dlc,
                        "data": message.data.hex(),
                        "is_extended_id": (
                            message.is_extended_id
                        ),
                    },
                )

                events.append(event)

                if (
                    max_events is not None
                    and len(events) >= max_events
                ):
                    break

        return events