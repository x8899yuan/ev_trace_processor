from pathlib import Path

from models.processed_trace import ProcessedTrace
from readers.reader_factory import ReaderFactory


class TraceProcessingService:
    """
    Coordinate trace processing operations.

    Workflow:

        trace file
            ↓
        ReaderFactory
            ↓
        Reader
            ↓
        ProcessedTrace
    """

    def process(
        self,
        file_path: Path,
    ) -> ProcessedTrace:
        """
        Process a trace file.
        """
        reader = ReaderFactory.get_reader(
            file_path
        )

        return reader.read(
            file_path
        )