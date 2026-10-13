from typing import List

from models.charging_session import ChargingSession
from models.decoded_can_message import DecodedCanMessage


class ChargingSessionService:
    def detect_sessions(
        self,
        messages: List[DecodedCanMessage]
    ) -> List[ChargingSession]:
        if not messages:
            return []

        session = ChargingSession(
            start_index=0,
            end_index=len(messages) - 1,
            message_count=len(messages)
        )

        return [session]