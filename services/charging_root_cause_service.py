class ChargingRootCauseService:
    def analyze(
        self,
        signal_values: dict[str, str],
    ) -> list[str]:

        findings: list[str] = []

        charge_permission_denied = (
            signal_values.get(
                "HVLM_CDO_LadeerlaubnisLm"
            )
            == "LadenNichtErlaubt"
        )

        vehicle_not_ready = (
            signal_values.get(
                "HVLM_CDO_LadebereitFzg"
            )
            == "keine_Ladebereitschaft"
        )

        readiness_not_achieved = (
            signal_values.get(
                "HVLM_CJ_LadebereitschaftFzg"
            )
            == "not_ready"
        )

        hv_contactor_issue = (
            signal_values.get(
                "HVLM_CDO_Status_Fahrzeug"
            )
            == "HVSchuetze_offen_o_Weld_Det"
        )

        charging_not_requested = (
            signal_values.get(
                "HVLM_Ladevorgang_Anf"
            )
            == "Laden_nicht_angefordert"
        )

        state_machine_error = (
            signal_values.get(
                "HVLM_ZustandLadeablauf"
            )
            == "Fehler"
        )

        if charge_permission_denied:
            findings.append(
                "Charging permission denied."
            )

        if vehicle_not_ready:
            findings.append(
                "Vehicle not ready for charging."
            )

        if readiness_not_achieved:
            findings.append(
                "Charging readiness not achieved."
            )

        if hv_contactor_issue:
            findings.append(
                "HV contactors open or weld detection active."
            )

        if charging_not_requested:
            findings.append(
                "Charging was not requested."
            )

        if state_machine_error:
            findings.append(
                "Charging state machine reports an error."
            )

        if (
            charge_permission_denied
            and vehicle_not_ready
        ):
            findings.append(
                "Root Cause: Charging session could not start because charging permission was denied while the vehicle was not in a charging-ready state."
            )

        if (
            hv_contactor_issue
            and state_machine_error
        ):
            findings.append(
                "Contributing Factor: HV contactor status and charging state machine error indicate a system-level charging inhibition."
            )

        if (
            charging_not_requested
            and readiness_not_achieved
        ):
            findings.append(
                "Observation: No successful charging request progression was observed."
            )

        if not findings:
            findings.append(
                "No charging root cause identified."
            )

        return findings