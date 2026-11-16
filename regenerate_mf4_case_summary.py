from pathlib import Path

from services.mf4_charging_analysis_service import Mf4ChargingAnalysisService
from services.mf4_report_service import Mf4ReportService


MF4_FILE = Path(r"data\MF4\VW31666_0173_20260508_140000h_Trace.MF4")


def main() -> None:
    if not MF4_FILE.exists():
        raise FileNotFoundError(f"MF4 file not found: {MF4_FILE}")

    analysis = Mf4ChargingAnalysisService().analyze(MF4_FILE)
    output_path = Mf4ReportService().save_report(analysis)
    print(output_path)


if __name__ == "__main__":
    main()
