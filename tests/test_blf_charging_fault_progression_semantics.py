from services.blf_charging_fault_correlation_service import BlfChargingFaultCorrelationService


def test_signal_changes_do_not_imply_charging_progression() -> None:
    service = BlfChargingFaultCorrelationService()
    state = {
        "HVLM_Ladevorgang_Anf": {
            "value_at_fault_start": "Laden_nicht_angefordert",
            "value_at_fault_end": "Laden_nicht_angefordert",
            "changes_during_fault": 0,
        },
        "HVLM_ZustandLadeablauf": {
            "value_at_fault_start": "Stby_Ladevorbed_nicht_erfuellt",
            "value_at_fault_end": "Stby_Ladevorbed_nicht_erfuellt",
            "changes_during_fault": 0,
        },
        "HVLM_CP_State_A": {
            "value_at_fault_start": "A",
            "value_at_fault_end": "A",
            "changes_during_fault": 2,
        },
    }
    assert service._charging_progressed(state) is False


def test_real_charging_state_advance_is_progression() -> None:
    service = BlfChargingFaultCorrelationService()
    state = {
        "HVLM_Ladevorgang_Anf": {
            "value_at_fault_start": "Laden_nicht_angefordert",
            "value_at_fault_end": "Laden_angefordert",
        },
        "HVLM_ZustandLadeablauf": {
            "value_at_fault_start": "Stby_Ladevorbed_nicht_erfuellt",
            "value_at_fault_end": "Laden_aktiv",
        },
    }
    assert service._charging_progressed(state) is True
