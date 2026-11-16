from pathlib import Path

from readers.blf_reader import BlfReader
from services.blf_signal_anomaly_service import BlfSignalAnomalyService
from services.dbc_decoder_service import DbcDecoderService


BLF_FILE = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")
DBC_FILE = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")
TARGET_CAN_IDS = {0x585, 0x5E7}
TARGET_SIGNALS = {
    "KL_Fehler_HV_Heizer",
    "KL_Fehler_HV_EKK",
    "SI_Sammel_SG_Fehler",
}


def test_blf_signal_anomaly_focused_real_blf() -> None:
    assert BLF_FILE.exists(), f"BLF file not found: {BLF_FILE}"
    assert DBC_FILE.exists(), f"DBC file not found: {DBC_FILE}"

    reader = BlfReader()
    decoder = DbcDecoderService()
    decoded_messages = []

    for event in reader.read_events(BLF_FILE):
        arbitration_id = event.payload.get("arbitration_id")
        data_hex = event.payload.get("data")
        if arbitration_id not in TARGET_CAN_IDS or not data_hex:
            continue
        try:
            decoded = decoder.decode_can_message(
                dbc_file=DBC_FILE,
                timestamp=event.timestamp.timestamp(),
                channel=event.payload.get("channel", 0),
                arbitration_id=arbitration_id,
                data=bytes.fromhex(data_hex),
            )
        except Exception:
            continue
        decoded.arbitration_id = arbitration_id
        decoded_messages.append(decoded)

    result = BlfSignalAnomalyService().analyze(decoded_messages)
    findings = {
        finding["signal"]: finding
        for finding in result["findings"]
        if finding["signal"] in TARGET_SIGNALS
    }

    print()
    for signal_name in sorted(TARGET_SIGNALS):
        finding = findings.get(signal_name)
        if finding is None:
            print(f"{signal_name}: no supported anomaly")
            continue
        print(f"{signal_name}: {finding['severity']}")
        print(f"  CAN ID: 0x{finding['arbitration_id']:X}")
        print(f"  Occurrences: {finding['occurrences']}")
        print(f"  Recovered: {finding['recovered']}")
        print(f"  Value counts: {finding['value_counts']}")
        print(f"  Transitions: {len(finding['transitions'])}")

    assert "KL_Fehler_HV_Heizer" in findings
    assert findings["KL_Fehler_HV_Heizer"]["severity"] == "FAULT"
    assert findings["KL_Fehler_HV_Heizer"]["arbitration_id"] == 0x5E7
    assert findings["KL_Fehler_HV_Heizer"]["value_counts"].get("Fehler", 0) > 0
    assert "KL_Fehler_HV_EKK" not in findings
    assert "SI_Sammel_SG_Fehler" in findings
    assert findings["SI_Sammel_SG_Fehler"]["severity"] == "WARNING"
