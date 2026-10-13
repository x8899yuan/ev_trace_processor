class ChargingEventDetectionService:

    EVENT_MAPPINGS = {
        (
            "HVLM_CDO_LadeerlaubnisLm",
            "LadenNichtErlaubt",
        ): "Charge permission denied",
        (
            "HVLM_CDO_LadebereitFzg",
            "keine_Ladebereitschaft",
        ): "Vehicle not ready for charging",
        (
            "HVLM_CJ_LadebereitschaftFzg",
            "not_ready",
        ): "Charging readiness not achieved",
        (
            "HVLM_CDO_Status_Fahrzeug",
            "HVSchuetze_offen_o_Weld_Det",
        ): "HV contactors open or weld detection active",
        (
            "HVLM_Ladevorgang_Anf",
            "Laden_nicht_angefordert",
        ): "Charging not requested",
        (
            "HVLM_ZustandLadeablauf",
            "Fehler",
        ): "Charging state machine entered error state",
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

            description = self.EVENT_MAPPINGS.get(
                (signal, value_text)
            )

            if not description:
                continue

            events.append(
                {
                    "timestamp": timeline_event["timestamp"],
                    "signal": signal,
                    "value": value_text,
                    "description": description,
                }
            )

        return events
