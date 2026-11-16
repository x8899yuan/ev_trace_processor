from services.session_trace_handlers import SessionTraceHandlers


def test_blf_connector_recognition_uses_structured_signal_values() -> None:
    charging = {
        "signal_values": {
            "HVLM_Steckerstatus_A": "kein_Stecker_erkannt",
            "HVLM_Steckerstatus_B": "kein_Stecker_erkannt",
            "STK_Stecker_Status": "kein_Stecker_erkannt",
            "HVLS_GBT_DcSteckerStatus": "nicht_erkannt",
        }
    }

    assert SessionTraceHandlers()._blf_connector_recognition(charging) == "NOT_RECOGNIZED"


def test_blf_control_pilot_recognition_uses_structured_signal_values() -> None:
    charging = {
        "signal_values": {
            "HVLM_CP_State_A": "A",
            "HVLM_CP_State_B": "kein_Zustand_erkannt",
            "HVLS_CP_Status_A": "CP_nicht_erkannt",
            "HVLS_CP_Frequenz_A": "keine_Frequenz_erkannt",
        }
    }

    assert SessionTraceHandlers()._blf_control_pilot_recognition(charging) == "NOT_ESTABLISHED"


def test_blf_prerequisite_classification_remains_indeterminate_without_evidence() -> None:
    handlers = SessionTraceHandlers()

    assert handlers._blf_connector_recognition({"signal_values": {}}) == "INDETERMINATE"
    assert handlers._blf_control_pilot_recognition({"signal_values": {}}) == "INDETERMINATE"
