from models.decoded_can_message import DecodedCanMessage


class SignalExtractionService:
    def extract(
        self,
        decoded_messages: list[DecodedCanMessage],
        signal_name: str,
    ) -> list[dict]:
        results: list[dict] = []

        for message in decoded_messages:
            if signal_name not in message.signals:
                continue

            results.append(
                {
                    "timestamp": message.timestamp,
                    "channel": message.channel,
                    "can_id": message.can_id,
                    "message_name": message.message_name,
                    "signal_name": signal_name,
                    "value": message.signals[signal_name],
                }
            )

        return results

    def available_signals(
        self,
        decoded_messages: list[DecodedCanMessage],
    ) -> list[str]:
        signals: set[str] = set()

        for message in decoded_messages:
            signals.update(message.signals.keys())

        return sorted(signals)

    def signal_exists(
        self,
        decoded_messages: list[DecodedCanMessage],
        signal_name: str,
    ) -> bool:
        for message in decoded_messages:
            if signal_name in message.signals:
                return True

        return False
