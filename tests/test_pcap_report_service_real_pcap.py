from pathlib import Path

import pytest

from readers.pcap_reader import PcapReader
from services.pcap_analysis_service import PcapAnalysisService
from services.pcap_report_service import PcapReportService


PCAP_FILE = Path(
    "data",
    "pcap",
    "20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap",
)


def get_real_pcap():
    if not PCAP_FILE.exists():
        pytest.skip(f"Real PCAP file not available: {PCAP_FILE}")
    return PCAP_FILE


@pytest.fixture(scope="module")
def analysis():
    trace = PcapReader().read(get_real_pcap())
    return PcapAnalysisService().analyze(trace)


@pytest.fixture
def reports(tmp_path, analysis):
    service = PcapReportService(output_directory=tmp_path / "pcap")
    return service.generate(analysis)


def read_report(path):
    return path.read_text(encoding="utf-8")


def test_real_pcap_generates_all_reports(reports):
    assert set(reports) == {
        "inventory",
        "statistics",
        "analysis",
        "case_summary",
    }
    for path in reports.values():
        assert path.exists()
        assert path.is_file()
        assert path.stat().st_size > 0


def test_real_pcap_report_file_names(reports):
    assert reports["inventory"].name == "pcap_inventory.txt"
    assert reports["statistics"].name == "pcap_statistics.txt"
    assert reports["analysis"].name == "pcap_analysis_report.txt"
    assert reports["case_summary"].name == "pcap_case_summary.txt"


def test_real_pcap_inventory_report(reports):
    content = read_report(reports["inventory"])
    assert "PCAP INVENTORY" in content
    assert PCAP_FILE.name in content
    assert "Packet count: 45,868" in content
    assert "Captured bytes: 40,475,619" in content
    assert "HOMEPLUG_AV: 45,868" in content
    assert "0x88e1: 45,868" in content
    assert "02:ab:01:d9:13:03 -> 00:00:ff:ff:00:ff" in content


def test_real_pcap_statistics_report(reports):
    content = read_report(reports["statistics"])
    assert "PCAP STATISTICS" in content
    assert "Frame-size distribution" in content
    assert "1319 bytes: 16,612 packets" in content
    assert "1317 bytes: 12,674 packets" in content
    assert "60 bytes: 12,438 packets" in content
    assert "454 bytes: 1,964 packets" in content
    assert "95 bytes: 1,931 packets" in content
    assert "198 bytes: 244 packets" in content
    assert "608 bytes: 5 packets" in content
    assert "Bin size: 10 seconds" in content
    assert "Baseline bins: 6" in content
    assert "Change factor: 2.0" in content


def test_real_pcap_analysis_report_capture_summary(reports):
    content = read_report(reports["analysis"])
    assert "PCAP ANALYSIS REPORT" in content
    assert "Packets: 45,868" in content
    assert "Start: 2025-04-01T17:57:01.062925+00:00" in content
    assert "End: 2025-04-01T18:18:04.331274+00:00" in content
    assert "Duration: 1263.268349 seconds" in content


def test_real_pcap_analysis_report_protocol(reports):
    content = read_report(reports["analysis"])
    assert "Protocol identification" in content
    assert "HOMEPLUG_AV: 45,868 packets" in content
    assert "02:ab:01:d9:13:03 -> 00:00:ff:ff:00:ff: 45,868 packets" in content


def test_real_pcap_analysis_report_transition(reports):
    content = read_report(reports["analysis"])
    assert "Transition analysis" in content
    assert "Baseline: 696.000 packets/bin" in content
    assert "Threshold: 1392.000 packets/bin" in content
    assert "Peak: 2,201 packets/bin" in content
    assert "Primary elevated-period start: 2025-04-01T18:00:11.062925+00:00" in content
    assert "Primary elevated-period end: 2025-04-01T18:01:01.062925+00:00" in content
    assert "Primary elevated-period packets: 10,536" in content
    assert "Pre-transition median: 753.000 packets/bin" in content
    assert "Transition average: 2107.200 packets/bin" in content
    assert "Post-transition median: 186.000 packets/bin" in content


def test_real_pcap_analysis_report_reduction_wording(reports):
    content = read_report(reports["analysis"])
    assert "Post-transition rate reduction vs baseline: 73.28%" in content
    assert "The median post-transition packet rate is 73.28% lower than the baseline." in content
    assert "Post vs baseline change: -73.28%" not in content


def test_real_pcap_analysis_report_prominent_frames(reports):
    content = read_report(reports["analysis"])
    assert "Transition-prominent frame sizes" in content
    assert "95 bytes: 1,691 transition packets, transition share=16.05%" in content
    assert "454 bytes: 1,690 transition packets, transition share=16.04%" in content


def test_real_pcap_analysis_report_preserves_limitations(reports):
    content = read_report(reports["analysis"])
    assert "Interpretation limitations" in content
    assert "It does not infer a physical power-loss cause, ECU fault, or HomePlug message semantics" in content


def test_real_pcap_case_summary(reports):
    content = read_report(reports["case_summary"])
    assert "PCAP CASE SUMMARY" in content
    assert PCAP_FILE.name in content
    assert "Packets analyzed: 45,868" in content
    assert "Protocols: HOMEPLUG_AV=45,868" in content
    assert "EtherTypes: 0x88e1=45,868" in content
    assert "Transition detected: Yes" in content
    assert "Elevated-period start: 2025-04-01T18:00:11.062925+00:00" in content
    assert "Elevated-period end: 2025-04-01T18:01:01.062925+00:00" in content


def test_real_pcap_case_summary_transition_metrics(reports):
    content = read_report(reports["case_summary"])
    assert "Baseline rate: 696.000 packets/bin" in content
    assert "Transition rate: 2107.200 packets/bin" in content
    assert "Post-transition rate: 186.000 packets/bin" in content
    assert "Post-transition rate reduction vs baseline: 73.28%" in content
    assert "Transition-prominent frame sizes: 95, 454" in content


def test_real_pcap_case_summary_does_not_assign_cause(reports):
    content = read_report(reports["case_summary"])
    assert "A measurable elevated traffic interval is followed by a lower persistent packet rate." in content
    assert "The report does not assign a physical cause to this transition." in content


def test_real_pcap_reports_use_temporary_output_directory(reports, tmp_path):
    expected_directory = tmp_path / "pcap"
    assert expected_directory.exists()
    assert all(path.parent == expected_directory for path in reports.values())
