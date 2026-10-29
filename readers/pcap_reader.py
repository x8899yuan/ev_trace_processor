from datetime import datetime, timezone
from pathlib import Path

import dpkt

from models.processed_trace import ProcessedTrace
from models.trace_event import TraceEvent
from models.trace_metadata import TraceMetadata
from readers.base_reader import BaseReader


class PcapReader(BaseReader):
    SUPPORTED_EXTENSION = ".pcap"

    def supports(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == self.SUPPORTED_EXTENSION

    def read(self, file_path: Path) -> ProcessedTrace:
        if not self.supports(file_path):
            raise ValueError(
                f"Unsupported PCAP file extension: {file_path.suffix}"
            )

        if not file_path.exists():
            raise FileNotFoundError(
                f"PCAP file not found: {file_path}"
            )

        metadata = TraceMetadata(
            file_path=file_path,
            trace_type="PCAP",
            file_size_bytes=file_path.stat().st_size,
        )

        events = []

        with file_path.open("rb") as file:
            reader = dpkt.pcap.Reader(file)

            for timestamp, buffer in reader:
                event = TraceEvent(
                    timestamp=datetime.fromtimestamp(
                        float(timestamp),
                        tz=timezone.utc,
                    ),
                    source_type="PCAP",
                    event_name="packet",
                    payload={
                        "raw_data": bytes(buffer),
                        "captured_length": len(buffer),
                    },
                )
                events.append(event)

        return ProcessedTrace(
            metadata=metadata,
            events=events,
        )
