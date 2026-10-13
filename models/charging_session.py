from dataclasses import dataclass


@dataclass
class ChargingSession:
    start_index: int
    end_index: int
    message_count: int