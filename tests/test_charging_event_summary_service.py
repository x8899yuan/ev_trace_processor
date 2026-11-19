from services.charging_event_summary_service import ChargingEventSummaryService


def test_repeated_samples_are_reported_as_observations():
    events = [
        {"signal": "HVLM_Ladevorgang_Anf", "value": "Laden_nicht_angefordert", "description": "Charging not requested"},
        {"signal": "HVLM_Ladevorgang_Anf", "value": "Laden_nicht_angefordert", "description": "Charging not requested"},
        {"signal": "HVLM_Ladevorgang_Anf", "value": "Laden_nicht_angefordert", "description": "Charging not requested"},
    ]
    summary = ChargingEventSummaryService().generate_summary(events)
    assert "Charging observations:       3" in summary
    assert "Distinct conditions:         1" in summary
    assert "Observations: 3" in summary
    assert 'No transition from "charging not requested"' in summary
    assert "Total events detected" not in summary


def test_empty_events_are_reported_without_failure_claim():
    summary = ChargingEventSummaryService().generate_summary([])
    assert "Charging observations:       0" in summary
    assert "No charging-related observations were detected." in summary
