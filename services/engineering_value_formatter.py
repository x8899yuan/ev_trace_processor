import re


class EngineeringValueFormatter:
    SIGNAL_LABELS = {
        "KL_Fehler_HV_Heizer": "HV heater fault",
        "HVLM_Steckerstatus_A": "connector status A",
        "HVLM_Steckerstatus_B": "connector status B",
        "STK_Stecker_Status": "connector status",
        "HVLS_GBT_DcSteckerStatus": "DC connector status",
        "HVLM_Ladevorgang_Anf": "charging request",
        "HVLM_ZustandLadeablauf": "charging sequence state",
        "HVLM_CP_State_A": "control-pilot state A",
        "HVLM_CP_State_B": "control-pilot state B",
        "HVLS_CP_Status_A": "control-pilot status A",
        "HVLS_CP_Frequenz_A": "control-pilot frequency A",
        "HVLS_CP_Tastgrad_A": "control-pilot duty cycle A",
        "HVLM_CP_MaxStrom_A": "control-pilot maximum current A",
        "HVLM_CP_MaxStrom_B": "control-pilot maximum current B",
        "HVLM_CDO_LadeerlaubnisLm": "charging permission",
        "HVLM_CDO_LadebereitFzg": "vehicle charging readiness",
        "HVLM_CJ_LadebereitschaftFzg": "vehicle charging readiness",
        "HVLM_CDO_Status_Fahrzeug": "vehicle charging status",
        "HVK_Ladebereit": "vehicle charging capability",
    }

    TRANSLATIONS = {
        "Stby_Ladevorbed_nicht_erfuellt": "standby, charging prerequisites not fulfilled",
        "Kein HV Fehler am HV Heizer erkannt": "no HV heater fault detected",
        "AC_DC_und_Induktiv_Ladebereit": "AC, DC and inductive charging ready",
        "Laden_nicht_angefordert": "charging not requested",
        "DC_Laden_Angefordert": "DC charging requested",
        "Kein_Laden_aktiv": "no charging active",
        "kein_Stecker_erkannt": "no connector detected",
        "Stecker_steckt_nicht_verriegelt": "connector inserted, not locked",
        "Stecker_steckt_und_verriegelt": "connector inserted and locked",
        "nicht_erkannt": "not detected",
        "kein_Zustand_erkannt": "no state detected",
        "keine_Frequenz_erkannt": "no frequency detected",
        "CP_erkannt": "control pilot detected",
        "CP_nicht_erkannt": "control pilot not detected",
        "HLC_Datenkommunikation": "HLC data communication",
        "unbekannt": "unknown",
        "nicht_bekannt": "unknown",
        "kein_Fehler": "no fault",
        "Fehler": "fault",
        "keine_Ladebereitschaft": "not ready for charging",
        "ladebereit": "ready for charging",
        "nicht_ladebereit": "not ready for charging",
        "aktiv": "active",
        "inaktiv": "inactive",
    }

    def format_signal_name(self, value) -> str:
        text = str(value)
        label = self.SIGNAL_LABELS.get(text)
        if not label:
            return text
        suffix = f" ({label})"
        return text if text.endswith(suffix) else text + suffix

    def format_value(self, value) -> str:
        text = str(value)
        translation = self.TRANSLATIONS.get(text)
        if not translation:
            return text
        suffix = f" ({translation})"
        return text if text.endswith(suffix) else text + suffix

    def format_text(self, text: str) -> str:
        result = text
        for original in sorted(self.SIGNAL_LABELS, key=len, reverse=True):
            formatted = self.format_signal_name(original)
            pattern = re.compile(
                rf"(?<![A-Za-z0-9_]){re.escape(original)}(?![A-Za-z0-9_]| \({re.escape(self.SIGNAL_LABELS[original])}\))"
            )
            result = pattern.sub(formatted, result)
        for original in sorted(self.TRANSLATIONS, key=len, reverse=True):
            translated = self.format_value(original)
            pattern = re.compile(
                rf"(?<![A-Za-z0-9_]){re.escape(original)}(?![A-Za-z0-9_]| \({re.escape(self.TRANSLATIONS[original])}\))"
            )
            result = pattern.sub(translated, result)
        return result
