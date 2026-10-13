from typing import List
from typing import Tuple


class ChargingDiagnosticService:

    def analyze_signal(
        self,
        signal_name: str,
        samples: List[Tuple[float, float]],
    ) -> dict:

        if not samples:
            return {
                "signal": signal_name,
                "sample_count": 0,
                "minimum": None,
                "maximum": None,
                "average": None,
                "delta": None,
                "trend": "no_data",
            }

        values = [
            value
            for _, value in samples
        ]

        minimum = min(values)
        maximum = max(values)
        average = sum(values) / len(values)

        first_value = values[0]
        last_value = values[-1]

        delta = last_value - first_value

        if delta > 0:
            trend = "increasing"
        elif delta < 0:
            trend = "decreasing"
        else:
            trend = "stable"

        return {
            "signal": signal_name,
            "sample_count": len(values),
            "minimum": minimum,
            "maximum": maximum,
            "average": average,
            "first_value": first_value,
            "last_value": last_value,
            "delta": delta,
            "trend": trend,
        }

    def detect_abnormal_drop(
        self,
        samples: List[Tuple[float, float]],
        threshold: float = 10.0,
    ) -> bool:

        if len(samples) < 2:
            return False

        values = [
            value
            for _, value in samples
        ]

        for index in range(
            1,
            len(values),
        ):
            drop = (
                values[index - 1]
                - values[index]
            )

            if drop >= threshold:
                return True

        return False

    def detect_flat_signal(
        self,
        samples: List[Tuple[float, float]],
    ) -> bool:

        if len(samples) < 2:
            return True

        values = [
            value
            for _, value in samples
        ]

        return min(values) == max(values)