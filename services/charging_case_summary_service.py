from pathlib import Path


class ChargingCaseSummaryService:
    def generate_summary(
        self,
        signal_values: dict[str, str],
        findings: list[str],
        output_dir: Path = Path("reports/charging"),
    ) -> Path:
        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        summary_path = (
            output_dir
            / "charging_case_summary.txt"
        )

        conclusion_prefixes = (
            "Root Cause:",
            "Contributing Factor:",
            "Observation:",
        )

        engineering_conclusions = []
        supporting_findings = []

        for finding in findings:
            if finding.startswith(conclusion_prefixes):
                engineering_conclusions.append(finding)
            else:
                supporting_findings.append(finding)

        with summary_path.open(
            "w",
            encoding="utf-8",
        ) as summary:
            summary.write(
                "CHARGING CASE SUMMARY\n"
            )

            summary.write(
                "=" * 80 + "\n\n"
            )

            summary.write(
                "EXECUTIVE SUMMARY\n"
            )

            summary.write(
                "-" * 80 + "\n"
            )

            summary.write(
                "Charging analysis completed successfully. "
                "The trace indicates that the charging session "
                "did not progress to a successful charging state.\n\n"
            )

            summary.write(
                "ENGINEERING CONCLUSION\n"
            )

            summary.write(
                "-" * 80 + "\n"
            )

            if engineering_conclusions:
                for conclusion in engineering_conclusions:
                    summary.write(
                        f"- {conclusion}\n"
                    )
            else:
                summary.write(
                    "- No engineering conclusion available.\n"
                )

            summary.write("\n")

            summary.write(
                "ROOT CAUSE EVIDENCE\n"
            )

            summary.write(
                "-" * 80 + "\n"
            )

            if supporting_findings:
                for finding in supporting_findings:
                    summary.write(
                        f"- {finding}\n"
                    )
            else:
                summary.write(
                    "- No supporting evidence available.\n"
                )

            summary.write("\n")

            summary.write(
                "SUPPORTING SIGNALS\n"
            )

            summary.write(
                "-" * 80 + "\n"
            )

            for signal_name, value in signal_values.items():
                summary.write(
                    f"{signal_name}: {value}\n"
                )

            summary.write("\n")

            summary.write(
                "ENGINEERING ASSESSMENT\n"
            )

            summary.write(
                "-" * 80 + "\n"
            )

            assessment_lines = []

            if "Charging permission denied." in findings:
                assessment_lines.append(
                    "* Charging authorization was denied."
                )

            if "Vehicle not ready for charging." in findings:
                assessment_lines.append(
                    "* Vehicle did not reach charging readiness."
                )

            if "Charging readiness not achieved." in findings:
                assessment_lines.append(
                    "* Charging readiness requirements were not met."
                )

            if "HV contactors open or weld detection active." in findings:
                assessment_lines.append(
                    "* HV contactor status prevented normal charging progression."
                )

            if "Charging was not requested." in findings:
                assessment_lines.append(
                    "* No valid charging request was observed."
                )

            if "Charging state machine reports an error." in findings:
                assessment_lines.append(
                    "* Charging workflow entered an error state."
                )

            if not assessment_lines:
                assessment_lines.append(
                    "* No charging issues identified."
                )

            for line in assessment_lines:
                summary.write(
                    f"{line}\n"
                )

            summary.write("\n")

            summary.write(
                "FINAL CONCLUSION\n"
            )

            summary.write(
                "-" * 80 + "\n"
            )

            root_causes = [
                finding
                for finding in findings
                if finding.startswith("Root Cause:")
            ]

            if root_causes:
                summary.write(
                    root_causes[0] + "\n"
                )
            else:
                summary.write(
                    "No definitive charging root cause was identified.\n"
                )

        return summary_path
