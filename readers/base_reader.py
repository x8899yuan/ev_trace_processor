from abc import ABC, abstractmethod
from pathlib import Path

from models.processed_trace import ProcessedTrace


class BaseReader(ABC):
    """
    Abstract base class for all trace readers.

    Concrete implementations include:

    - BLFReader
    - PCAPReader
    - DLTReader
    """

    @abstractmethod
    def supports(self, file_path: Path) -> bool:
        """
        Return True if this reader supports the file.
        """
        raise NotImplementedError

    @abstractmethod
    def read(self, file_path: Path) -> ProcessedTrace:
        """
        Read a trace file and return a ProcessedTrace.
        """
        raise NotImplementedError