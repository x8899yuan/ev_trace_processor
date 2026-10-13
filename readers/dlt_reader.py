from pathlib import Path

from models.processed_trace import ProcessedTrace
from models.trace_metadata import TraceMetadata
from readers.base_reader import BaseReader


class DltReader(BaseReader):
    """
    Reader for DLT trace files.

    Milestone 1 implementation:
    - Validate file extension
    - Validate file existence
    - Create metadata
    - Return empty ProcessedTrace

    Actual DLT parsing will be added later.
    """

    SUPPORTED_EXTENSION = ".dlt"

    def supports(self, file_path: Path) -> bool:
        """
        Return True if the file is a DLT trace.
        """
        return (
            file_path.suffix.lower()
            == self.SUPPORTED_EXTENSION
        )

    def read(self, file_path: Path) -> ProcessedTrace:
        """
        Read a DLT file.
        """
        if not file_path.exists():
            raise FileNotFoundError(
                f"DLT file not found: {file_path}"
            )

        metadata = TraceMetadata(
            file_path=file_path,
            trace_type="DLT",
            file_size_bytes=file_path.stat().st_size,
        )

        return ProcessedTrace(
            metadata=metadata
        )