from pathlib import Path

import pytest

from services.mf4_charging_analysis_service import Mf4ChargingAnalysisService


MF4_DIR = Path("data") / "MF4"


def _discover_mf4_file() -> Path:
    files = sorted(
        path
        for path in MF4_DIR.iterdir()
        if path.is_file() and path.suffix.lower() == ".mf4"
    ) if MF4_DIR.exists() else []
    if not files:
        pytest.skip(f"No MF4 real-trace fixture found under {MF4_DIR}")
    return files[0]


def test_mf4_charging_analysis_real_trace() -> None:
    mf4_file = _discover_mf4_file()
    result = Mf4ChargingAnalysisService().analyze(mf4_file)

    assert Path(result["source_file"]).resolve() == mf4_file.resolve()
    assert result["charging_progression"] in {"OBSERVED", "NOT_OBSERVED", "INDETERMINATE"}
    assert result["connector_recognition"] in {"RECOGNIZED", "NOT_RECOGNIZED", "INDETERMINATE"}
    assert result["control_pilot_recognition"] in {"ESTABLISHED", "NOT_ESTABLISHED", "INDETERMINATE"}
    assert isinstance(result["cp_fault_observed"], bool)
    assert result["root_cause_status"] in {"CONFIRMED", "UNCONFIRMED"}

    findings = result["findings"]
    assert isinstance(findings, dict)
    assert findings

    required_keys = {
        "connector_a",
        "connector_b",
        "connector_sensor",
        "dc_plug_status",
        "cp_state_a",
        "cp_state_b",
        "cp_status_a",
        "charge_request",
        "active_charge_type",
        "vehicle_ready_plc",
    }
    assert required_keys.intersection(findings)

    for entry in findings.values():
        assert entry["name"]
        assert isinstance(entry["group"], int)
        assert isinstance(entry["index"], int)
        assert entry["samples"] >= 0
        assert entry["transitions"] >= 0
        assert isinstance(entry.get("unique_values", []), list)
        assert entry.get("invalid_timestamp_count", 0) >= 0
        if entry["samples"] > 0:
            assert entry["first_value"] is not None
            assert entry["last_value"] is not None
