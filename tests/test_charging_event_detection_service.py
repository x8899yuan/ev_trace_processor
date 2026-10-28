from services.charging_event_detection_service import ChargingEventDetectionService


def make_timeline(signal, value, timestamp=123.456):
    return [
        {
            "timestamp": timestamp,
            "signal": signal,
            "old_value": None,
            "new_value": value,
        }
    ]


def test_charge_permission_denied_classification():
    events = ChargingEventDetectionService().detect_events(
        make_timeline("HVLM_CDO_LadeerlaubnisLm", "LadenNichtErlaubt")
    )

    assert events == [
        {
            "timestamp": 123.456,
            "signal": "HVLM_CDO_LadeerlaubnisLm",
            "value": "LadenNichtErlaubt",
            "description": "Charge permission denied",
            "event_type": "CHARGING_PERMISSION_DENIED",
            "category": "charging_inhibition",
        }
    ]


def test_vehicle_not_ready_classification():
    events = ChargingEventDetectionService().detect_events(
        make_timeline("HVLM_CDO_LadebereitFzg", "keine_Ladebereitschaft")
    )

    assert events[0]["event_type"] == "VEHICLE_NOT_READY"
    assert events[0]["category"] == "charging_readiness"


def test_charging_readiness_not_achieved_classification():
    events = ChargingEventDetectionService().detect_events(
        make_timeline("HVLM_CJ_LadebereitschaftFzg", "not_ready")
    )

    assert events[0]["event_type"] == "CHARGING_READINESS_NOT_ACHIEVED"
    assert events[0]["category"] == "charging_readiness"


def test_hv_contactor_classification():
    events = ChargingEventDetectionService().detect_events(
        make_timeline("HVLM_CDO_Status_Fahrzeug", "HVSchuetze_offen_o_Weld_Det")
    )

    assert events[0]["event_type"] == "HV_CONTACTOR_OPEN_OR_WELD_DETECTION"
    assert events[0]["category"] == "high_voltage_system"


def test_charging_not_requested_classification():
    events = ChargingEventDetectionService().detect_events(
        make_timeline("HVLM_Ladevorgang_Anf", "Laden_nicht_angefordert")
    )

    assert events[0]["event_type"] == "CHARGING_NOT_REQUESTED"
    assert events[0]["category"] == "charging_request"


def test_charging_state_machine_error_classification():
    events = ChargingEventDetectionService().detect_events(
        make_timeline("HVLM_ZustandLadeablauf", "Fehler")
    )

    assert events[0]["event_type"] == "CHARGING_STATE_MACHINE_ERROR"
    assert events[0]["category"] == "charging_state"


def test_unknown_signal_value_is_ignored():
    events = ChargingEventDetectionService().detect_events(
        make_timeline("HVLM_ZustandLadeablauf", "Normal")
    )

    assert events == []


def test_numeric_value_is_normalized_to_string():
    service = ChargingEventDetectionService()
    service.EVENT_MAPPINGS = {
        ("ExampleSignal", "1"): {
            "description": "Example event",
            "event_type": "EXAMPLE_EVENT",
            "category": "example",
        }
    }

    events = service.detect_events(make_timeline("ExampleSignal", 1))

    assert events[0]["value"] == "1"
