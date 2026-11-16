from datetime import datetime, timedelta

from services.session_trace_handlers import SessionTraceHandlers


def test_fault_summary_counts_intervals_recoveries_and_active_end() -> None:
    start = datetime(2026, 5, 8, 14, 0, 0)
    samples = [
        {"timestamp": start, "value": "Kein HV Fehler am HV Heizer erkannt"},
        {"timestamp": start + timedelta(seconds=1), "value": "Fehler"},
        {"timestamp": start + timedelta(seconds=2), "value": "Fehler"},
        {"timestamp": start + timedelta(seconds=3), "value": "Kein HV Fehler am HV Heizer erkannt"},
        {"timestamp": start + timedelta(seconds=4), "value": "Fehler"},
    ]

    result = SessionTraceHandlers()._fault_summary("KL_Fehler_HV_Heizer", samples)

    assert result["signal_name"] == "KL_Fehler_HV_Heizer"
    assert result["fault_value"] == "Fehler"
    assert result["fault_intervals"] == 2
    assert result["recoveries"] == 1
    assert result["active_at_trace_end"] is True
    assert result["charging_causal_status"] == "UNCONFIRMED"
