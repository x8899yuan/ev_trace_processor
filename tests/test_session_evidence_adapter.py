from services.session_evidence_adapter import TestSessionEvidenceAdapter


def test_adapter_uses_authoritative_dlt_category_totals_not_example_lengths() -> None:
    analysis = {
        "capture": {"trace_count": 1, "source_files": ["session.dlt"], "event_count": 1000},
        "finding_category_counts": {
            "critical": 100,
            "error": 2000,
            "warning": 3000,
            "keyword_observation": 4000,
        },
        "critical_findings": [{"message": "sample"}] * 25,
        "error_findings": [{"message": "sample"}] * 25,
        "warning_findings": [{"message": "sample"}] * 25,
    }

    result = TestSessionEvidenceAdapter().adapt_dlt(analysis)

    assert result["fault_findings"] == [
        "CRITICAL findings: 100",
        "ERROR findings: 2000",
        "WARNING findings: 3000",
    ]
    assert len(result["critical_findings"]) == 25
    assert len(result["error_findings"]) == 25
    assert len(result["warning_findings"]) == 25


def test_adapter_preserves_zero_dlt_category_totals() -> None:
    analysis = {
        "capture": {"trace_count": 1, "source_files": ["session.dlt"], "event_count": 1},
        "finding_category_counts": {"critical": 0, "error": 0, "warning": 0},
    }

    result = TestSessionEvidenceAdapter().adapt_dlt(analysis)

    assert result["fault_findings"] == [
        "CRITICAL findings: 0",
        "ERROR findings: 0",
        "WARNING findings: 0",
    ]
