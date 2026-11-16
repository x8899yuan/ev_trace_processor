from pathlib import Path

import pytest

from readers.dlt_reader import DltReader
from services.dlt_analysis_service import DltAnalysisService


DLT_DIRECTORY = Path("data") / "dlt"
SAMPLE_SIZE = 10000

DLT_FILES = [
    "VW31666_0173_20260508_140000h_DLT_ICAS1_AdaptiveVM.dlt",
    "VW31666_0173_20260508_140000h_DLT_ICAS1_HousekeepingVM.dlt",
    "VW31666_0173_20260508_140000h_DLT_ICAS1_JavaVM.dlt",
    "VW31666_0173_20260508_140000h_DLT_ICAS1_R7.dlt",
]


def get_real_dlt_files():
    paths = [DLT_DIRECTORY / name for name in DLT_FILES]
    missing = [path for path in paths if not path.exists()]

    if missing:
        pytest.skip(
            "Real DLT files not available: "
            + ", ".join(str(path) for path in missing)
        )

    return paths


@pytest.fixture(scope="module")
def analysis():
    traces = [
        DltReader(max_events=SAMPLE_SIZE).read(path)
        for path in get_real_dlt_files()
    ]
    return DltAnalysisService().analyze(traces)


def test_real_dlt_capture_summary(analysis):
    capture = analysis["capture"]

    assert capture["trace_count"] == 4
    assert capture["event_count"] == 40000
    assert capture["source_files"] == DLT_FILES
    assert capture["start_timestamp"].isoformat() == "2026-05-11T04:34:53.637410+00:00"
    assert capture["end_timestamp"].isoformat() == "2026-05-11T05:16:23.192400+00:00"
    assert capture["duration_seconds"] == pytest.approx(2489.55499)


def test_real_dlt_source_file_counts(analysis):
    assert analysis["source_file_counts"] == {
        DLT_FILES[3]: 10000,
        DLT_FILES[2]: 10000,
        DLT_FILES[0]: 10000,
        DLT_FILES[1]: 10000,
    }


def test_real_dlt_ecu_counts(analysis):
    assert analysis["ecu_counts"] == {
        "C002": 10000,
        "8124": 10000,
        "8123": 10000,
        "C003": 10000,
    }


def test_real_dlt_severity_counts(analysis):
    assert analysis["severity_counts"] == {
        "INFO": 36016,
        "ERROR": 2702,
        "WARN": 1017,
        "CONTROL": 106,
        "APP_TRACE": 82,
        "DEBUG": 62,
        "VERBOSE": 14,
        "FATAL": 1,
    }


def test_real_dlt_verbosity_counts(analysis):
    assert analysis["verbosity_counts"] == {
        "non_verbose": 9546,
        "verbose": 30454,
    }


def test_real_dlt_finding_categories(analysis):
    assert analysis["finding_category_counts"] == {
        "error": 2702,
        "keyword_observation": 1270,
        "warning": 1017,
        "critical": 1,
    }


def test_real_dlt_keyword_counts(analysis):
    assert analysis["keyword_counts"] == {
        "failed": 2232,
        "error": 2202,
        "timeout": 239,
        "disconnected": 223,
        "shutdown": 214,
        "reset": 192,
        "disconnect": 98,
        "timed out": 83,
        "invalid": 37,
        "failure": 14,
        "terminated": 13,
        "exception": 12,
        "unavailable": 2,
    }


def test_real_dlt_unique_finding_signatures(analysis):
    assert analysis["unique_finding_signature_count"] == 539
    assert len(analysis["finding_signatures"]) == 25


def test_real_dlt_fatal_finding(analysis):
    assert len(analysis["critical_findings"]) == 1

    finding = analysis["critical_findings"][0]

    assert finding["source_file"] == DLT_FILES[2]
    assert finding["ecu_id"] == "8124"
    assert finding["application_id"] == "CSC"
    assert finding["context_id"] == "MC1"
    assert finding["severity"] == "FATAL"
    assert finding["event_name"] == "CSC.MC1"
    assert finding["message"] == "Socket connection to gateway is broken"


def test_real_dlt_repeated_service_registry_error_signature(analysis):
    signatures = analysis["finding_signatures"]

    matches = [
        item
        for item in signatures
        if item["source_file"] == DLT_FILES[1]
        and item["application_id"] == "SR"
        and item["context_id"] == "SR"
        and item["signature"] == "[sr] error : failed to add sd service to serviceregistry."
    ]

    assert len(matches) == 1
    assert matches[0]["category"] == "error"
    assert matches[0]["severity"] == "ERROR"
    assert matches[0]["occurrence_count"] == 446
    assert set(matches[0]["matched_terms"]) == {"error", "failed"}


def test_real_dlt_udp_multicast_failure_signature(analysis):
    signatures = analysis["finding_signatures"]

    matches = [
        item
        for item in signatures
        if item["source_file"] == DLT_FILES[1]
        and item["application_id"] == "CSC"
        and item["context_id"] == "MMxx"
        and item["signature"]
        == "udpmulticastsendersocket: sending udp multicast failed. error: <num> - operation not permitted"
    ]

    assert len(matches) == 1
    assert matches[0]["occurrence_count"] == 323
    assert set(matches[0]["matched_terms"]) == {"error", "failed"}


def test_real_dlt_r7_reset_signature(analysis):
    signatures = analysis["finding_signatures"]

    matches = [
        item
        for item in signatures
        if item["source_file"] == DLT_FILES[3]
        and item["application_id"] == "RESM"
        and item["context_id"] == "ERR"
        and item["signature"]
        == "[res][poweron restart][past reset]: printing reset reason.."
    ]

    assert len(matches) == 1
    assert matches[0]["category"] == "error"
    assert matches[0]["occurrence_count"] == 155
    assert matches[0]["matched_terms"] == ["reset"]


def test_real_dlt_reset_count_is_false_positive_resistant(analysis):
    assert analysis["keyword_counts"]["reset"] == 192
    assert analysis["keyword_counts"]["reset"] < 466


def test_real_dlt_factory_reset_identifier_not_counted_as_reset_keyword(analysis):
    observations = analysis["warning_findings"] + analysis["keyword_observations"]

    factory_reset_messages = [
        item
        for item in observations
        if "FactoryResetController" in item["message"]
    ]

    assert all(
        "reset" not in item["matched_terms"]
        for item in factory_reset_messages
    )


def test_real_dlt_application_and_context_inventory(analysis):
    assert analysis["application_counts"]["TOP"] == 13035
    assert analysis["application_counts"]["ASR4"] == 6766
    assert analysis["application_counts"]["SR"] == 3654
    assert analysis["context_counts"]["CPU"] == 12029
    assert analysis["context_counts"]["Info"] == 6776
    assert analysis["context_counts"]["DFLT"] == 2241


def test_real_dlt_timeline_accounts_for_all_events(analysis):
    timeline = analysis["timeline"]

    assert timeline
    assert timeline[0]["bin_index"] == 0
    assert timeline[0]["start_timestamp"] == analysis["capture"]["start_timestamp"]
    assert sum(row["event_count"] for row in timeline) == 40000


def test_real_dlt_timeline_severity_accounting(analysis):
    totals = {}

    for row in analysis["timeline"]:
        for severity, count in row["severity_counts"].items():
            totals[severity] = totals.get(severity, 0) + count

    assert totals == analysis["severity_counts"]


def test_real_dlt_analysis_parameters(analysis):
    parameters = analysis["analysis_parameters"]

    assert parameters["bin_seconds"] == 10
    assert parameters["top_n"] == 25
    assert "error" in parameters["finding_terms"]
    assert "reset" in parameters["finding_terms"]
    assert "timeout" in parameters["finding_terms"]
