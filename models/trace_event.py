from dataclasses import dataclass, field
from typing import Any, Dict
from datetime import datetime


@dataclass(slots=True)
class TraceEvent:
    """
    Represents a normalized trace event produced by any reader.

    Readers for BLF, PCAP, and DLT should convert their native
    records into this common format.
    """

    timestamp: datetime
    source_type: str
    event_name: str
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary.
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_type": self.source_type,
            "event_name": self.event_name,
            "payload": self.payload,
        }

    @property
    def payload_size(self) -> int:
        """
        Return the number of payload fields.
        """
        return len(self.payload)

    def has_payload(self) -> bool:
        """
        Return True when payload contains data.
        """
        return bool(self.payload)