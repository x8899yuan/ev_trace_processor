from services.charging_timeline_service import ChargingTimelineService


def test_charging_timeline_initial_state_and_transitions() -> None:
    signal_samples = {
        "HVLM_CDO_LadeerlaubnisLm": [
            {"timestamp": 100.0, "value": "LadenNichtErlaubt"},
            {"timestamp": 101.0, "value": "LadenNichtErlaubt"},
            {"timestamp": 102.0, "value": "LadenErlaubt"},
        ],
        "HVLM_ZustandLadeablauf": [
            {"timestamp": 99.0, "value": "Fehler"},
            {"timestamp": 103.0, "value": "Fehler"},
            {"timestamp": 104.0, "value": "Bereit"},
        ],
    }

    timeline = ChargingTimelineService().build_timeline(signal_samples)

    assert timeline == [
        {
            "timestamp": 99.0,
            "signal": "HVLM_ZustandLadeablauf",
            "old_value": None,
            "new_value": "Fehler",
            "event_type": "INITIAL_STATE",
        },
        {
            "timestamp": 100.0,
            "signal": "HVLM_CDO_LadeerlaubnisLm",
            "old_value": None,
            "new_value": "LadenNichtErlaubt",
            "event_type": "INITIAL_STATE",
        },
        {
            "timestamp": 102.0,
            "signal": "HVLM_CDO_LadeerlaubnisLm",
            "old_value": "LadenNichtErlaubt",
            "new_value": "LadenErlaubt",
            "event_type": "TRANSITION",
        },
        {
            "timestamp": 104.0,
            "signal": "HVLM_ZustandLadeablauf",
            "old_value": "Fehler",
            "new_value": "Bereit",
            "event_type": "TRANSITION",
        },
    ]
