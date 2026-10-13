from typing import Dict, List


class ChargingRecommendationService:
    """
    Generates engineering investigation recommendations based on
    detected charging root causes and diagnostic findings.
    """

    def generate(
        self,
        diagnostics: List[str] | None = None,
        root_causes: List[str] | None = None,
    ) -> str:
        diagnostics = diagnostics or []
        root_causes = root_causes or []

        recommendations = []

        combined_text = " ".join(
            [str(item) for item in diagnostics + root_causes]
        ).lower()

        if (
            "permission denied" in combined_text
            or "ladeerlaubnis" in combined_text
        ):
            recommendations.append(
                "Verify why charging authorization was denied and review charging permission prerequisites."
            )

        if (
            "not ready" in combined_text
            or "ladebereit" in combined_text
            or "readiness" in combined_text
        ):
            recommendations.append(
                "Investigate vehicle charging readiness conditions and prerequisite signals."
            )

        if (
            "hv contactor" in combined_text
            or "hvschuetze" in combined_text
            or "weld detection" in combined_text
        ):
            recommendations.append(
                "Review HV contactor status, weld detection logic, and HV system interlocks."
            )

        if (
            "not requested" in combined_text
            or "charging request" in combined_text
        ):
            recommendations.append(
                "Verify charger-to-vehicle request sequencing and charging initiation logic."
            )

        if "error state" in combined_text or "fehler" in combined_text:
            recommendations.append(
                "Investigate charging state machine error conditions and associated fault codes."
            )

        if not recommendations:
            recommendations.append(
                "Review charging timeline and related signals to determine the cause of the charging interruption."
            )

        recommendations.append(
            "Correlate findings with DTCs, charger logs, and vehicle logging data for further validation."
        )

        report_lines = [
            "CHARGING RECOMMENDATIONS",
            "=" * 80,
            "",
            "RECOMMENDED INVESTIGATION ACTIONS",
            "-" * 80,
        ]

        for index, recommendation in enumerate(recommendations, start=1):
            report_lines.append(f"{index}. {recommendation}")

        report_lines.append("")
        report_lines.append("NEXT STEPS")
        report_lines.append("-" * 80)
        report_lines.append(
            "Perform the recommended investigations and validate all charging prerequisites before repeating charging tests."
        )

        return "\n".join(report_lines)