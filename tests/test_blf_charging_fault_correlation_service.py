from services.blf_charging_fault_correlation_service import (
    BlfChargingFaultCorrelationService,
)


def sample(timestamp, value):
    return {"timestamp": timestamp, "value": value}


def test_correlates_fault_interval_with_stable_charging_states() -> None:
    fault_samples = [
        sample(1.0, "Kein HV Fehler am HV Heizer erkannt"),
        sample(2.0, "Fehler"),
        sample(3.0, "Fehler"),
        sample(4.0, "Kein HV Fehler am HV Heizer erkannt"),
    ]
    charging_samples = {
        "HVLM_Ladevorgang_Anf": [
            sample(1.0, "Laden_nicht_angefordert"),
            sample(5.0, "Laden_nicht_angefordert"),
        ],
        "HVLM_ZustandLadeablauf": [
            sample(1.0, "Stby_Ladevorbed_nicht_erfuellt"),
            sample(5.0, "Stby_Ladevorbed_nicht_erfuellt"),
        ],
    }

    result = BlfChargingFaultCorrelationService().correlate(
        fault_signal="KL_Fehler_HV_Heizer",
        fault_samples=fault_samples,
        charging_samples=charging_samples,
    )

    assert result["fault_interval_count"] == 1
    assert result["recovered_interval_count"] == 1
    interval = result["fault_intervals"][0]
    assert interval["start_timestamp"] == 2.0
    assert interval["end_timestamp"] == 4.0
    assert interval["duration_seconds"] == 2.0
    assert interval["recovered"] is True
    assert interval["charging_progressed_during_fault"] is False
    assert interval["charging_state"]["HVLM_Ladevorgang_Anf"]["value_at_fault_start"] == "Laden_nicht_angefordert"


def test_reports_unrecovered_fault_at_end() -> None:
    result = BlfChargingFaultCorrelationService().correlate(
        fault_signal="KL_Fehler_HV_Heizer",
        fault_samples=[sample(1.0, "Fehler"), sample(2.0, "Fehler")],
        charging_samples={},
    )

    assert result["fault_interval_count"] == 1
    assert result["persistent_at_end"] is True
    assert result["fault_intervals"][0]["recovered"] is False
    assert result["fault_intervals"][0]["end_timestamp"] is None
