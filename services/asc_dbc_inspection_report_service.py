from collections import Counter
from pathlib import Path


class AscDbcInspectionReportService:
    TARGET_SIGNALS = (
        "VIN_01",
        "HVLM_Steckerstatus_A",
        "HVLM_Steckerstatus_B",
        "HVLM_CP_State_A",
        "HVLM_CP_State_B",
        "HVLM_CP_MaxStrom_A",
        "HVLM_CP_MaxStrom_B",
        "HVLM_Ladevorgang_Anf",
        "HVLM_ZustandLadeablauf",
        "KL_Fehler_HV_Heizer",
    )

    def generate(self, analysis: dict, output_path: Path) -> Path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        samples = analysis.get("signal_samples") or []
        signal_counts = Counter(str(sample.get("signal_name")) for sample in samples)
        target_counts = {name: signal_counts.get(name, 0) for name in self.TARGET_SIGNALS}
        hvlm_counts = Counter(
            str(sample.get("signal_name"))
            for sample in samples
            if str(sample.get("signal_name", "")).startswith("HVLM_")
        )
        message_count = int(analysis.get("message_count", 0) or 0)
        matched = int(analysis.get("matched_message_count", 0) or 0)
        decoded = int(analysis.get("decoded_message_count", 0) or 0)
        failures = int(analysis.get("decode_failure_count", 0) or 0)
        lines = [
            "ASC DBC INSPECTION REPORT",
            "=" * 80,
            "",
            "SOURCE",
            "-" * 80,
            f"ASC file: {analysis.get('source_file', 'source not supplied')}",
            "",
            "DBC COVERAGE",
            "-" * 80,
            f"ASC CAN/CAN-FD messages: {message_count}",
            f"DBC-matched messages: {matched}",
            f"DBC match coverage: {self._percentage(matched, message_count)}",
            f"Successfully decoded messages: {decoded}",
            f"Decode success among matched: {self._percentage(decoded, matched)}",
            f"Decode failures: {failures}",
            f"Decoded signal samples: {analysis.get('decoded_signal_count', 0)}",
            f"Unique decoded messages: {analysis.get('unique_decoded_message_count', 0)}",
            f"Unique decoded signals: {analysis.get('unique_decoded_signal_count', 0)}",
            "",
            "TOP DECODED DBC MESSAGES",
            "-" * 80,
            *self._message_count_lines(analysis.get("message_name_counts") or {}, 20),
            "",
            "TOP UNMATCHED CAN IDS",
            "-" * 80,
            *self._id_rows(analysis.get("unmatched_can_ids") or [], 20),
            "",
            "TOP DECODE-FAILURE CAN IDS",
            "-" * 80,
            *self._id_rows(analysis.get("decode_failure_can_ids") or [], 20),
            "",
            "ENGINEERING SIGNAL PRESENCE",
            "-" * 80,
        ]
        for name in self.TARGET_SIGNALS:
            lines.append(f"{name}: {'OBSERVED' if target_counts[name] else 'NOT_OBSERVED'} | samples={target_counts[name]}")
        lines.extend([
            "",
            "HVLM SIGNAL INVENTORY",
            "-" * 80,
            *self._message_count_lines(dict(hvlm_counts.most_common()), 50),
            "",
            "VIN EVIDENCE STATUS",
            "-" * 80,
            *self._vin_lines(samples),
            "",
            "CHARGING EVIDENCE STATUS",
            "-" * 80,
            *self._charging_lines(target_counts),
            "",
        ])
        output.write_text("\n".join(lines), encoding="utf-8")
        return output

    def _percentage(self, numerator: int, denominator: int) -> str:
        if denominator <= 0:
            return "0.00%"
        return f"{100.0 * numerator / denominator:.2f}%"

    def _message_count_lines(self, counts: dict, limit: int) -> list[str]:
        if not counts:
            return ["None observed."]
        return [f"{name}: {count}" for name, count in list(counts.items())[:limit]]

    def _id_rows(self, rows: list[dict], limit: int) -> list[str]:
        if not rows:
            return ["None observed."]
        return [f"{row.get('hex_id', 'unknown')}: {row.get('count', 0)}" for row in rows[:limit]]

    def _vin_lines(self, samples: list[dict]) -> list[str]:
        vin_samples = [sample for sample in samples if sample.get("signal_name") == "VIN_01"]
        if not vin_samples:
            return ["VIN_01 was not independently decoded from the ASC evidence."]
        values = []
        for sample in vin_samples:
            value = str(sample.get("value", "")).strip()
            if value and value not in values:
                values.append(value)
        lines = [f"VIN_01 samples: {len(vin_samples)}"]
        if values:
            lines.append("Observed decoded VIN_01 values: " + ", ".join(values[:10]))
        return lines

    def _charging_lines(self, counts: dict[str, int]) -> list[str]:
        groups = {
            "Connector evidence": ("HVLM_Steckerstatus_A", "HVLM_Steckerstatus_B"),
            "Control Pilot state evidence": ("HVLM_CP_State_A", "HVLM_CP_State_B"),
            "Control Pilot current evidence": ("HVLM_CP_MaxStrom_A", "HVLM_CP_MaxStrom_B"),
            "Charging request evidence": ("HVLM_Ladevorgang_Anf",),
            "Charging workflow evidence": ("HVLM_ZustandLadeablauf",),
            "HV heater fault evidence": ("KL_Fehler_HV_Heizer",),
        }
        return [
            f"{label}: {'AVAILABLE' if any(counts.get(name, 0) for name in names) else 'NOT_OBSERVED'}"
            for label, names in groups.items()
        ]
