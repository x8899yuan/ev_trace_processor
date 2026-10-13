from collections import defaultdict
from typing import Dict
from typing import List
from typing import Set

from models.decoded_can_message import DecodedCanMessage


class SignalCatalogService:
    def build_catalog(
        self,
        messages: List[DecodedCanMessage]
    ) -> Dict[str, Set[str]]:
        catalog: Dict[str, Set[str]] = defaultdict(set)

        for message in messages:
            message_name = getattr(message, "message_name", None)

            if not message_name:
                continue

            signals = getattr(message, "signals", {})

            for signal_name in signals.keys():
                catalog[message_name].add(signal_name)

        return dict(catalog)

    def get_message_names(
        self,
        messages: List[DecodedCanMessage]
    ) -> List[str]:
        return sorted(
            {
                message.message_name
                for message in messages
                if getattr(message, "message_name", None)
            }
        )

    def get_signal_names(
        self,
        messages: List[DecodedCanMessage]
    ) -> List[str]:
        signal_names: Set[str] = set()

        for message in messages:
            signals = getattr(message, "signals", {})
            signal_names.update(signals.keys())

        return sorted(signal_names)

    def get_message_count(
        self,
        messages: List[DecodedCanMessage]
    ) -> int:
        return len(self.get_message_names(messages))

    def get_signal_count(
        self,
        messages: List[DecodedCanMessage]
    ) -> int:
        return len(self.get_signal_names(messages))
