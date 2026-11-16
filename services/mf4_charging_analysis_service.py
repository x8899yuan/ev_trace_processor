from pathlib import Path

import numpy as np
from asammdf import MDF


class Mf4ChargingAnalysisService:
    CHANNELS = {
        "bms_charging_active": "ev.BMS_Ladevorgang_aktiv",
        "vehicle_charge_capable": "ev.HVK_Ladebereit",
        "active_charge_type": "ev.HVLM_Aktive_Ladeart",
        "charge_request": "ev.HVLM_Ladevorgang_Anf",
        "vehicle_ready_cdo": "ev.HVLM_CDO_LadebereitFzg",
        "vehicle_ready_cj": "ev.HVLM_CJ_LadebereitschaftFzg",
        "vehicle_ready_plc": "ev.HVLM_LadebereitFzgPlc",
        "connector_a": "ev.HVLM_Steckerstatus_A",
        "connector_b": "ev.HVLM_Steckerstatus_B",
        "connector_sensor": "ev.STK_Stecker_Status",
        "cp_state_a": "ev.HVLM_CP_State_A",
        "cp_state_b": "ev.HVLM_CP_State_B",
        "cp_fault_a": "ev.HVLM_CP_Fehlerzustand_A",
        "cp_fault_b": "ev.HVLM_CP_Fehlerzustand_B",
        "cp_protocol_a": "ev.HVLM_CP_KommProtokoll_A",
        "cp_protocol_b": "ev.HVLM_CP_KommProtokoll_B",
        "cp_max_current_a": "ev.HVLM_CP_MaxStrom_A",
        "cp_max_current_b": "ev.HVLM_CP_MaxStrom_B",
        "cp_status_a": "ev.HVLS_CP_Status_A",
        "cp_frequency_a": "ev.HVLS_CP_Frequenz_A",
        "cp_duty_a": "ev.HVLS_CP_Tastgrad_A",
        "dc_plug_status": "ev.HVLS_GBT_DcSteckerStatus",
        "cdo_lock_status": "ev.HVLM_CDO_SteckerVerEntr_Status",
        "cj_lock_status": "ev.HVLM_CJ_SteckerVerEntr_Status",
    }
    INVALID_TIMESTAMP_THRESHOLD = 1_000_000_000.0

    def analyze(self, mf4_file: Path) -> dict:
        mf4_file = Path(mf4_file)
        findings = {}
        duplicates = {}

        with MDF(mf4_file) as measurement:
            for key, name in self.CHANNELS.items():
                occurrences = measurement.channels_db.get(name, ())
                if not occurrences:
                    continue

                entries = []
                for group_index, channel_index in occurrences:
                    signal = measurement.get(
                        name,
                        group=group_index,
                        index=channel_index,
                    )
                    entries.append(
                        self._signal_result(
                            name,
                            group_index,
                            channel_index,
                            signal,
                        )
                    )

                findings[key] = entries[0]
                if len(entries) > 1:
                    duplicates[name] = entries

        return {
            "source_file": str(mf4_file),
            "findings": findings,
            "duplicates": duplicates,
            "charging_progression": self._charging_progression(findings),
            "connector_recognition": self._connector_recognition(findings),
            "control_pilot_recognition": self._control_pilot_recognition(findings),
            "cp_fault_observed": self._cp_fault_observed(findings),
            "root_cause_status": "UNCONFIRMED",
        }

    def _signal_result(self, name, group_index, channel_index, signal) -> dict:
        samples = signal.samples
        timestamps = signal.timestamps
        values = [self._text(value) for value in samples]
        valid_timestamps = [
            float(value)
            for value in timestamps
            if 0 <= float(value) < self.INVALID_TIMESTAMP_THRESHOLD
        ]

        return {
            "name": name,
            "group": group_index,
            "index": channel_index,
            "unit": signal.unit or "",
            "samples": len(samples),
            "first_value": values[0] if values else None,
            "last_value": values[-1] if values else None,
            "transitions": self._transitions(values),
            "valid_first_timestamp": valid_timestamps[0] if valid_timestamps else None,
            "valid_last_timestamp": valid_timestamps[-1] if valid_timestamps else None,
            "invalid_timestamp_count": len(timestamps) - len(valid_timestamps),
            "unique_values": sorted(set(values)),
        }

    def _charging_progression(self, findings) -> str:
        inactive = self._values(findings, "bms_charging_active")
        active_type = self._values(findings, "active_charge_type")
        request = self._values(findings, "charge_request")
        if inactive == {"inaktiv"} and active_type == {"Kein_Laden_aktiv"} and request == {"Laden_nicht_angefordert"}:
            return "NOT_OBSERVED"
        return "INDETERMINATE"

    def _connector_recognition(self, findings) -> str:
        expected = {
            "connector_a": "kein_Stecker_erkannt",
            "connector_b": "kein_Stecker_erkannt",
            "connector_sensor": "kein_Stecker_erkannt",
            "dc_plug_status": "nicht_erkannt",
        }
        observed = 0
        for key, value in expected.items():
            values = self._values(findings, key)
            if value in values:
                observed += 1
        return "NOT_RECOGNIZED" if observed >= 3 else "INDETERMINATE"

    def _control_pilot_recognition(self, findings) -> str:
        state_a = self._values(findings, "cp_state_a")
        state_b = self._values(findings, "cp_state_b")
        cp_status = self._values(findings, "cp_status_a")
        if "A" in state_a and "kein_Zustand_erkannt" in state_b and "CP_nicht_erkannt" in cp_status:
            return "NOT_ESTABLISHED"
        return "INDETERMINATE"

    def _cp_fault_observed(self, findings) -> bool:
        a = self._values(findings, "cp_fault_a")
        b = self._values(findings, "cp_fault_b")
        return not (a == {"kein_Fehler"} and b == {"kein_Fehler"})

    def _values(self, findings, key) -> set[str]:
        entry = findings.get(key)
        if not entry:
            return set()
        return set(entry["unique_values"])

    def _transitions(self, values) -> int:
        return sum(
            values[index] != values[index - 1]
            for index in range(1, len(values))
        )

    def _text(self, value) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        if isinstance(value, np.generic):
            value = value.item()
        return str(value)
