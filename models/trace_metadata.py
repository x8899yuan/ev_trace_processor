from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass(slots=True)
class TraceMetadata:
    """
    File-level metadata describing a trace file.
    """

    file_path: Path
    trace_type: str
    file_size_bytes: int

    start_timestamp: Optional[datetime] = None
    end_timestamp: Optional[datetime] = None

    event_count: int = 0

    @property
    def file_name(self) -> str:
        """
        Return the trace filename.
        """
        return self.file_path.name

    @property
    def duration_seconds(self) -> Optional[float]:
        """
        Return trace duration in """
        if self.start_timestamp is None:
            return None

        if self.end_timestamp is None:
            return None

        return (
            self.end_timestamp - self.start_timestamp
        ).total_seconds()

    @property
    def has_events(self) -> bool:
        """
        Return True if the trace contains events.
        """
        return self.event_count > 0

    def to_dict(self) -> dict:
        """
        Convert metadata to a dictionary.
        """
        return {
            "file_name": self.file_name,
            "file_path": str(self.file_path),
            "trace_type": self.trace_type,
            "file_size_bytes": self.file_size_bytes,
            "start_timestamp": (
                self.start_timestamp.isoformat()
                if self.start_timestamp
                else None
            ),
            "end_timestamp": (
                self.end_timestamp.isoformat()
                if self.end_timestamp
                else None
            ),
            "duration_seconds": self.duration_seconds,
            "event_count": self.event_count,
        }