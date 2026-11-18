from pathlib import Path

import pytest


LEGACY_BLF = Path("data") / "blf" / "VW31666_0173_20260508_140000h_Trace.blf"
LEGACY_DLT_DIR = Path("data") / "dlt"
LEGACY_DLT_NAMES = (
    "VW31666_0173_20260508_140000h_DLT_ICAS1_AdaptiveVM.dlt",
    "VW31666_0173_20260508_140000h_DLT_ICAS1_HousekeepingVM.dlt",
    "VW31666_0173_20260508_140000h_DLT_ICAS1_JavaVM.dlt",
    "VW31666_0173_20260508_140000h_DLT_ICAS1_R7.dlt",
)
LEGACY_DLT = tuple(LEGACY_DLT_DIR / name for name in LEGACY_DLT_NAMES)

LEGACY_BLF_TESTS = {
    "test_blf_additional_faults_targeted_real_blf.py",
    "test_blf_charging_fault_correlation_real_blf.py",
    "test_blf_charging_prerequisites_targeted_real_blf.py",
    "test_blf_inventory_report_real_blf.py",
    "test_blf_signal_anomaly_focused_real_blf.py",
    "test_blf_signal_anomaly_real_blf.py",
    "test_blf_statistics_report_real_blf.py",
    "test_blf_vehicle_inventory_extractor_real_blf.py",
    "test_charging_analysis_real_blf.py",
    "test_charging_analysis_timestamp_channel_real_blf.py",
    "test_hvlm_targeted_extraction_real_blf.py",
    "test_hvlm_transition_count_real_blf.py",
}


def pytest_collection_modifyitems(config, items):
    blf_missing = not LEGACY_BLF.exists()
    dlt_missing = any(not path.exists() for path in LEGACY_DLT)
    blf_skip = pytest.mark.skip(reason=f"Legacy BLF fixture not available: {LEGACY_BLF}")
    bundle_skip = pytest.mark.skip(reason="Legacy VW31666_0173 real-bundle fixtures are not fully available")

    for item in items:
        filename = Path(str(item.fspath)).name
        if blf_missing and filename in LEGACY_BLF_TESTS:
            item.add_marker(blf_skip)
        if filename == "test_session_trace_handlers_real_bundle.py" and (blf_missing or dlt_missing):
            item.add_marker(bundle_skip)
