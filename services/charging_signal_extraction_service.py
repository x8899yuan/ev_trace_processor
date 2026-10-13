from typing import List, Tuple

from models.decoded_can_message import DecodedCanMessage


class ChargingSignalExtractionService:

    def extract_signal(
        self,
        decoded_messages: List[DecodedCanMessage],
        signal_name: str,
    ) -> List[Tuple[float, float]]:
        samples = []

        for message in decoded_messages:
            if signal_name not in message.signals:
                continue

            value = message.signals[signal_name]

            try:
                samples.append(
                    (
                        message.timestamp,
                        float(value),
                    )
                )
            except (
                TypeError,
                ValueError,
            ):
                continue

        return samples

    def extract_multiple_signals(
        self,
        decoded_messages: List[DecodedCanMessage],
        signal_names: List[str],
    ) -> dict[str, List[Tuple[float, float]]]:
        results = {}

        for signal_name in signal_names:
            results[signal_name] = self.extract_signal(
                decoded_messages,
                signal_name,
            )

        return results