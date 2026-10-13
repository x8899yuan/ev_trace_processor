from typing import Dict, List


class ChargingDiagnosticReportService:
    """
    Generates a comprehensive engineering diagnostic report
    including root causes, supporting evidence, and
    investigation recommendations.
    """

    def generate(
        self,
        diagnostics: List[str],
        root_causes: List[str],
        supporting_signals: Dict[str, str],
        engineering_conclusions: List[str],
        recommendations: str | None = None,
    ) -> str:

        report_lines = [
            "CHARGING DIAGNOSTIC REPORT",
            "=" * 80,
            "",
            "ENGINEERING CONCLUSION",
            "-" * 80,
        ]

        for conclusion in engineering_conclusions:
            report_lines.append(f"- {conclusion}")

        report_lines.extend(
            [
                "",
                "ROOT CAUSE SUMMARY",
                "-" * 80,
            ]
        )

        for cause in root_causes:
            report_lines.append(f"- {cause}")

        report_lines.extend(
            [
                "",
                "SUPPORTING SIGNALS",
                "-" * 80,
            ]
        )

        for signal_name, signal_value in supporting_signals.items():
            report_lines.append(
                f"{signal_name}: {signal_value}"
            )

        report_lines.extend(
            [
                "",
                "DIAGNOSTIC ASSESSMENT",
                "-" * 80,
            ]
        )

        for diagnostic in diagnostics:
            report_lines.append(f"* {diagnostic}")

        if recommendations:
            report_lines.extend(
                [
                    "",
                    "RECOMMENDED INVESTIGATION ACTIONS",
                    "-" * 80,
                    "",
                    recommendations,
                ]
            )

        return "\n".join(report_lines)