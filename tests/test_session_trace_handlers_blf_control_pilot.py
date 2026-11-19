from services.session_trace_handlers import SessionTraceHandlers


def _recognition(signal_values):
    return SessionTraceHandlers()._blf_control_pilot_recognition(
        {"signal_values": signal_values}
    )


def test_state_a_and_no_secondary_state_are_not_established():
    assert _recognition(
        {
            "HVLM_CP_State_A": "A",
            "HVLM_CP_State_B": "kein_Zustand_erkannt",
        }
    ) == "NOT_ESTABLISHED"


def test_explicit_cp_not_recognized_is_not_established():
    assert _recognition(
        {"HVLS_CP_Status_A": "CP_nicht_erkannt"}
    ) == "NOT_ESTABLISHED"


def test_missing_cp_evidence_is_indeterminate():
    assert _recognition({}) == "INDETERMINATE"


def test_progressed_cp_state_is_not_falsely_not_established():
    assert _recognition(
        {
            "HVLM_CP_State_A": "C",
            "HVLM_CP_State_B": "kein_Zustand_erkannt",
        }
    ) == "INDETERMINATE"
