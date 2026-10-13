from dataclasses import dataclass
from typing import Any


@dataclass
class DecodedCanMessage:
    timestamp: float
    channel: int
    can_id: int
    message_name: str
    dlc: int
    signals: dict[str, Any]