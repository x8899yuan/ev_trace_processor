class ChargingEventDetectionService:

    EVENT_MAPPINGS = {
        (
            "HVLM_CDO_LadeerlaubnisLm",
            "LadenNichtErlaubt",
        ): {
            "description": "Charge permission denied",
            "event_type": "CHARGING_PERMISSION_DENIED",
            "category": "charging_inhibition",
        },
        (
            "HVLM_CDO_LadebereitFzg",
            "keine_Ladebereitschaft",
        ): {
            "description": "Vehicle not ready for charging",
            "event_type": "VEHICLE_NOT_READY",
            "category": "charging_readiness",
        },
        (
            "HVLM_CJ_LadebereitschaftFzg",
            "not_ready",
        ): {
            "description": "Charging readiness not achieved",
            "event_type": "CHARGING_READINESS_NOT_ACHIEVED",
            "category": "charging_readiness",
        },
        (
            "HVLM_CDO_Status_Fahrzeug",
            "HVSchuetze_offen_o_Weld_Det",
        ): {
            "description": "HV contactors open or weld detection active",
            "event_type": "HV_CONTACTOR_OPEN_OR_WELD_DETECTION",
            "category": "high_voltage_system",
        },
        (
            "HVLM_Ladevorgang_Anf",
            "Laden_nicht_angefordert",
        ): {
            "description": "Charging not requested",
            "event_type": "CHARGING_NOT_REQUESTED",
            "category": "charging_request",
        },
        (
            "HVLM_ZustandLadeablauf",
            "Fehler",
        ): {
            "description": "Charging state machine entered error state",
            "event_type": "CHARGING_STATE_MACHINE_ERROR",
            "category": "charging_state",
        },
    }

    def detect_events(
        self,
        timeline: list[dict],
    ) -> list[dict]:

        events: list[dict] = []

        for timeline_event in timeline:

            signal = timeline_event["signal"]
            value = timeline_event["new_value"]
            value_text = str(value)

            classification = self.EVENT_MAPPINGS.get(
                (signal, value_text)
            )

            if not classification:
                continue

            events.append(
                {
                    "timestamp": timeline_event["timestamp"],
                    "signal": signal,
                    "value": value_text,
                    "description": classification["description"],
                    "event_type": classification["event_type"],
                    "category": classification["category"],
                }
            )

        return events
