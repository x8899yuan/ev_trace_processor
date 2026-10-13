from services.charging_recommendation_service import (
    ChargingRecommendationService,
)


def test_charging_recommendation_service_real_blf():
    diagnostics = [
        "Charging authorization was not granted.",
        "Vehicle not in a charging-ready state.",
        "Charging readiness requirements were not achieved.",
        "HV system prevented charge initiation.",
        "No charging request was observed.",
        "Charging workflow ended in an error state.",
    ]

    root_causes = [
        "Charging permission denied.",
        "Vehicle not ready for charging.",
        "Charging readiness not achieved.",
        "HV contactors open or weld detection active.",
        "Charging was not requested.",
        "Charging state machine reports an error.",
    ]

    service = ChargingRecommendationService()

    report = service.generate(
        diagnostics=diagnostics,
        root_causes=root_causes,
    )

    assert report is not None
    assert len(report) > 0

    assert "CHARGING RECOMMENDATIONS" in report
    assert "RECOMMENDED INVESTIGATION ACTIONS" in report
    assert "NEXT STEPS" in report

    assert "charging authorization" in report.lower()
    assert "charging readiness" in report.lower()
    assert "hv contactor" in report.lower()
    assert "charging initiation" in report.lower()
    assert "state machine" in report.lower()

    print()
    print("=" * 80)
    print("CHARGING RECOMMENDATIONS")
    print("=" * 80)
    print(report)
