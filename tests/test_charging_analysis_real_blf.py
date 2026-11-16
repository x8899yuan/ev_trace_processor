from pathlib import Path

from services.charging_analysis_service import ChargingAnalysisService


BLF_FILE = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")
DBC_FILE = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")


def test_charging_analysis_real_blf() -> None:
    assert BLF_FILE.exists(), f"BLF file not found: {BLF_FILE}"
    assert DBC_FILE.exists(), f"DBC file not found: {DBC_FILE}"

    result = ChargingAnalysisService().analyze(
        blf_file=BLF_FILE,
        dbc_file=DBC_FILE,
    )

    assert result["target_can_ids"] == [0x271, 0x272, 0x5E7]
