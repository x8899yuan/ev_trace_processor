from typing import Dict, List

from models.decoded_can_message import DecodedCanMessage


class ChargingSignalDiscoveryService:
    CHARGING_KEYWORDS = [
        "charge",
        "charging",
        "charger",
        "soc",
        "battery",
        "batt",
        "hv",
        "dc",
        "ac",
        "evse",
        "plug",
        "pilot",
        "contactor",
        "dcc",
        "dccurrent",
        "current",
        "voltage",
        "energy",
        "power",
        "obc",
        "dcdc",
        "cp",
        "pp",
    ]

    def discover(
        self,
        decoded_messages: List[DecodedCanMessage],
    ) -> Dict[str, List[str]]:
        discovered_signals = set()

        for message in decoded_messages:
            for signal_name in message.signals.keys():
                discovered_signals.add(signal_name)

        charging_signals = []
        non_charging_signals = []

        for signal_name in sorted(discovered_signals):
            signal_lower = signal_name.lower()

            if any(
                keyword in signal_lower
                for keyword in self.CHARGING_KEYWORDS
            ):
                charging_signals.append(signal_name)
            else:
                non_charging_signals.append(signal_name)

        return {
            "charging_signals": charging_signals,
            "non_charging_signals": non_charging_signals,
            "total_signals": len(discovered_signals),
            "charging_signal_count": len(charging_signals),
        }