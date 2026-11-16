from pathlib import Path

from readers.blf_reader import BlfReader
from services.blf_charging_fault_correlation_service import (
    BlfChargingFaultCorrelationService,
)
from services.dbc_decoder_service import DbcDecoderService


BLF_FILE = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")
DBC_FILE = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")
TARGET_CAN_IDS = {0x272, 0x5E7}
FAULT_SIGNAL = "KL_Fehler_HV_Heizer"
CHARGING_SIGNALS = (
    "HVLM_Ladevorgang_Anf",
    "HVLM_ZustandLadeablauf",
)
NORMAL_FAULT_VALUE = "Kein HV Fehler am HV Heizer erkannt"
FAULT_VALUE = "Fehler"


def test_blf_charging_fault_correlation_real_blf() -> None:
    assert BLF_FILE.exists(), f"BLF file not found: {BLF_FILE}"
    assert DBC_FILE.exists(), f"DBC file not found: {DBC_FILE}"

    reader = BlfReader()
    decoder = DbcDecoderService()
    fault_samples = []
    charging_samples = {signal: [] for signal in CHARGING_SIGNALS}
    matched_frames = {can_id: 0 for can_id in TARGET_CAN_IDS}

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

        matched_frames[arbitration_id] += 1

        if arbitration_id == 0x5E7 and FAULT_SIGNAL in decoded.signals:
            fault_samples.append(
                {
                    "timestamp": decoded.timestamp,
                    "value": decoded.signals[FAULT_SIGNAL],
                }
            )

        if arbitration_id == 0x272:
            for signal_name in CHARGING_SIGNALS:
                if signal_name not in decoded.signals:
                    continue
                charging_samples[signal_name].append(
                    {
                        "timestamp": decoded.timestamp,
                        "value": decoded.signals[signal_name],
                    }
                )

    assert fault_samples
    assert all(charging_samples[signal] for signal in CHARGING_SIGNALS)

    result = BlfChargingFaultCorrelationService().correlate(
        fault_signal=FAULT_SIGNAL,
        fault_samples=fault_samples,
        charging_samples=charging_samples,
        abnormal_values={FAULT_VALUE},
        normal_values={NORMAL_FAULT_VALUE},
    )

    print()
    print(f"Matched 0x272 frames: {matched_frames[0x272]}")
    print(f"Matched 0x5E7 frames: {matched_frames[0x5E7]}")
    print(f"HV heater samples: {len(fault_samples)}")
    print(f"Fault intervals: {result['fault_interval_count']}")
    print(f"Recovered intervals: {result['recovered_interval_count']}")
    print(f"Persistent at end: {result['persistent_at_end']}")
    print("-" * 100)

    for index, interval in enumerate(result["fault_intervals"], start=1):
        print(f"Fault interval {index}")
        print(f"  Start: {interval['start_timestamp']}")
        print(f"  End: {interval['end_timestamp']}")
        print(f"  Duration: {interval['duration_seconds']}")
        print(f"  Abnormal samples: {interval['abnormal_samples']}")
        print(f"  Recovered: {interval['recovered']}")
        print(
            f"  Charging progressed during fault: "
            f"{interval['charging_progressed_during_fault']}"
        )

        for signal_name in CHARGING_SIGNALS:
            state = interval["charging_state"][signal_name]
            print(f"  {signal_name}")
            print(f"    At fault start: {state['value_at_fault_start']}")
            print(f"    At fault end: {state['value_at_fault_end']}")
            print(f"    Changes during fault: {state['changes_during_fault']}")

        if index >= 10 and result["fault_interval_count"] > 10:
            print(
                f"... {result['fault_interval_count'] - 10} "
                f"additional fault intervals omitted"
            )
            break

    assert matched_frames[0x272] == 16192
    assert matched_frames[0x5E7] > 0
    assert result["fault_interval_count"] > 0

    for interval in result["fault_intervals"]:
        request_state = interval["charging_state"]["HVLM_Ladevorgang_Anf"]
        sequence_state = interval["charging_state"]["HVLM_ZustandLadeablauf"]

        assert request_state["value_at_fault_start"] == "Laden_nicht_angefordert"
        assert sequence_state["value_at_fault_start"] == "Stby_Ladevorbed_nicht_erfuellt"
        assert request_state["changes_during_fault"] == 0
        assert sequence_state["changes_during_fault"] == 0
        assert interval["charging_progressed_during_fault"] is False
