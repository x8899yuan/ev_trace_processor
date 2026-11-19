from services.session_summary_service import TestSessionSummaryService


def test_dlt_category_counts_are_rendered_once_and_descriptive_findings_remain():
    dlt = {
        "source_files": ["a.dlt", "b.dlt", "c.dlt", "d.dlt"],
        "fault_findings": [
            "DLT diagnostic evidence",
            "CRITICAL findings: 100",
            "ERROR findings: 257744",
            "WARNING findings: 98432",
        ],
        "finding_category_counts": {
            "critical": 100,
            "error": 257744,
            "warning": 98432,
            "keyword_observation": 121969,
        },
        "severity_counts": {
            "INFO": 2522390,
            "ERROR": 257744,
            "WARN": 98432,
            "FATAL": 100,
        },
    }
    report = TestSessionSummaryService().generate_summary(dlt=dlt)
    assert "DLT diagnostic evidence" in report
    assert report.count("CRITICAL findings: 100") == 1
    assert report.count("ERROR findings: 257744") == 1
    assert report.count("WARNING findings: 98432") == 1
    assert report.count("KEYWORD_OBSERVATION findings: 121969") == 1
    assert "Severity counts: INFO=2522390, ERROR=257744, WARN=98432, FATAL=100" in report


def test_dlt_source_list_is_preserved():
    dlt = {
        "source_files": ["a.dlt", "b.dlt", "c.dlt", "d.dlt"],
        "finding_category_counts": {},
    }
    report = TestSessionSummaryService().generate_summary(dlt=dlt)
    assert "DLT: ANALYZED | a.dlt, b.dlt, c.dlt, d.dlt" in report
