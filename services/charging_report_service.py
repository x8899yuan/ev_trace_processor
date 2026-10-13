from pathlib import Path
from typing import Dict


class ChargingReportService:
    def generate_report(
        self,
        analysis: Dict,
        abnormal_drop: bool,
        flat_signal: bool,
        output_dir: Path = Path("reports/charging"),
    ) -> Path:
        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        signal_name = analysis["signal"]

        report_path = (
            output_dir
            / f"{signal_name}_report.txt"
        )

        findings = []

        if abnormal_drop:
            findings.append(
                "Potential abnormal signal drop detected."
            )
        else:
            findings.append(
                "No abnormal signal drop detected."
            )

        if flat_signal:
            findings.append(
                "Signal remained constant."
            )
        else:
            findings.append(
                "Signal values changed over time."
            )

        trend = analysis["trend"]

        if trend == "decreasing":
            findings.append(
                "Signal trend is decreasing."
            )
        elif trend == "increasing":
            findings.append(
                "Signal trend is increasing."
            )
        else:
            findings.append(
                "Signal trend is stable."
            )

        with report_path.open(
            "w",
            encoding="utf-8",
        ) as report:
            report.write(
                "CHARGING DIAGNOSTIC REPORT\n"
            )
            report.write(
                "=" * 60 + "\n\n"
            )
            report.write(
                f"Signal: {analysis['signal']}\n"
            )
            report.write(
                f"Sample Count: {analysis['sample_count']}\n"
            )
            report.write(
                f"Minimum: {analysis['minimum']}\n"
            )
            report.write(
                f"Maximum: {analysis['maximum']}\n"
            )
            report.write(
                f"Average: {analysis['average']:.2f}\n"
            )
            report.write(
                f"First Value: {analysis['first_value']}\n"
            )
            report.write(
                f"Last Value: {analysis['last_value']}\n"
            )
            report.write(
                f"Delta: {analysis['delta']}\n"
            )
            report.write(
                f"Trend: {analysis['trend']}\n"
            )
            report.write(
                f"Abnormal Drop: {abnormal_drop}\n"
            )
            report.write(
                f"Flat Signal: {flat_signal}\n"
            )
            report.write("\n")
            report.write("FINDINGS\n")
            report.write(
                "-" * 60 + "\n"
            )

            for finding in findings:
                report.write(
                    f"- {finding}\n"
                )

        return report_path
