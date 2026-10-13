from pathlib import Path

from readers.base_reader import BaseReader
from readers.blf_reader import BlfReader
from readers.pcap_reader import PcapReader
from readers.dlt_reader import DltReader


class ReaderFactory:
    """
    Factory for selecting the appropriate reader
    based on file extension.
    """

    _readers: list[BaseReader] = [
        BlfReader(),
        PcapReader(),
        DltReader(),
    ]

    @classmethod
    def get_reader(
        cls,
        file_path: Path,
    ) -> BaseReader:
        """
        Return the first reader that supports the file.
        """
        for reader in cls._readers:
            if reader.supports(file_path):
                return reader

        raise ValueError(
            f"No reader available for file: {file_path}"
        )