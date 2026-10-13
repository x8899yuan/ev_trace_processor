from pathlib import Path
from typing import Set


class Settings:
    """Application configuration settings."""

    def __init__(self) -> None:
        self.project_root = Path(__file__).resolve().parent.parent

        self.data_folder = self.project_root / "data"
        self.dbc_folder = self.project_root / "dbc"
        self.report_folder = self.project_root / "reports"

        self.supported_trace_extensions: Set[str] = {
            ".blf",
            ".pcap",
            ".dlt",
        }

        self.recursive_trace_search = True

    def is_supported_trace_file(self, file_path: Path) -> bool:
        """Return True if the file extension is supported."""
        return file_path.suffix.lower() in self.supported_trace_extensions