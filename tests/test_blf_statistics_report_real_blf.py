from pathlib import Path

from readers.blf_reader import BlfReader
from services.blf_statistics_report_service import BlfStatisticsReportService
from services.blf_statistics_service import BlfStatisticsService


BLF_FILE = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")


def test_real_blf_statistics_report() -> None:
    trace = BlfReader().read(BLF_FILE)
    statistics = BlfStatisticsService().analyze(trace)
    report_service = BlfStatisticsReportService()
    report = report_service.generate_report(statistics)

    print()
    print(report)
    print()

    assert "BLF Statistics Report" in report
    assert "Total Frames:" in report
    assert "Duration (s):" in report
    assert "Frames per Second:" in report
    assert "Unique CAN IDs:" in report
    assert "Channel Count:" in report
    assert "Standard Frames:" in report
    assert "Extended Frames:" in report
    assert "Busiest CAN ID:" in report
    assert "Busiest Channel:" in report

    report_path = report_service.save_report(statistics, BLF_FILE.name)

    assert report_path.exists()
    assert report_path.is_file()
    assert report_path.suffix == ".txt"
    assert report_path.parent.name == "blf"
    assert report_path.name == "blf_statistics.txt"
