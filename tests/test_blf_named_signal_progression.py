from services.blf_charging_fault_correlation_service import BlfChargingFaultCorrelationService


class NamedSignalValue:
    __hash__ = None

    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value


def test_unhashable_named_signal_values_do_not_crash_or_imply_progression() -> None:
    state = {
        "HVLM_Ladevorgang_Anf": {
            "value_at_fault_start": NamedSignalValue("Laden_nicht_angefordert"),
            "value_at_fault_end": NamedSignalValue("Laden_nicht_angefordert"),
        },
        "HVLM_ZustandLadeablauf": {
            "value_at_fault_start": NamedSignalValue("Stby_Ladevorbed_nicht_erfuellt"),
            "value_at_fault_end": NamedSignalValue("Stby_Ladevorbed_nicht_erfuellt"),
        },
    }

    assert BlfChargingFaultCorrelationService()._charging_progressed(state) is False


def test_unhashable_named_signal_values_detect_real_progression() -> None:
    state = {
        "HVLM_Ladevorgang_Anf": {
            "value_at_fault_start": NamedSignalValue("Laden_nicht_angefordert"),
            "value_at_fault_end": NamedSignalValue("Laden_angefordert"),
        },
        "HVLM_ZustandLadeablauf": {
            "value_at_fault_start": NamedSignalValue("Stby_Ladevorbed_nicht_erfuellt"),
            "value_at_fault_end": NamedSignalValue("Laden_aktiv"),
        },
    }

    assert BlfChargingFaultCorrelationService()._charging_progressed(state) is True
