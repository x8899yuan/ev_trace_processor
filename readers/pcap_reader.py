from pathlib import Path

from models.processed_trace import ProcessedTrace
from models.trace_metadata import TraceMetadata
from readers.base_reader import BaseReader


class PcapReader(BaseReader):
    """
    Reader for PCAP trace files.

    Milestone 1 implementation:
    - Validate file extension
    - Validate file existence
    - Create metadata
    - Return empty ProcessedTrace

    Actual PCAP parsing will be added later.
    """

    SUPPORTED_EXTENSION = ".pcap"

    def supports(self, file_path: Path) -> bool:
        """
        Return True if the file is a PCAP trace.
        """
        return (
            file_path.suffix.lower()
            == self.SUPPORTED_EXTENSION
        )

    def read(self, file_path: Path) -> ProcessedTrace:
        """
        Read a PCAP file.
        """
        if not file_path.exists():
            raise FileNotFoundError(
                f"PCAP file not found: {file_path}"
            )

        metadata = TraceMetadata(
            file_path=file_path,
            trace_type="PCAP",
            file_size_bytes=file_path.stat().st_size,
        )

        return ProcessedTrace(
            metadata=metadata
        )