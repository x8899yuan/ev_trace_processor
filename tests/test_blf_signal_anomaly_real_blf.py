from pathlib import Path

from readers.blf_reader import BlfReader
from services.blf_signal_anomaly_service import BlfSignalAnomalyService
from services.dbc_decoder_service import DbcDecoderService


BLF_FILE = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")
DBC_FILE = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")


def test_blf_signal_anomaly_real_blf() -> None:
    assert BLF_FILE.exists(), f"BLF file not found: {BLF_FILE}"
    assert DBC_FILE.exists(), f"DBC file not found: {DBC_FILE}"

    anomaly_service = BlfSignalAnomalyService()
    decoder = DbcDecoderService()
    target_ids = set()
    candidate_signals_by_id = {}

    for arbitration_id in range(0x800):
        try:
            if not decoder.message_exists(DBC_FILE, arbitration_id):
                continue
            decoded = decoder.decode_can_message(
                dbc_file=DBC_FILE,
                timestamp=0.0,
                channel=0,
                arbitration_id=arbitration_id,
                data=bytes(64),
            )
        except Exception:
            continue

        candidates = sorted(
            signal_name
            for signal_name in decoded.signals
            if anomaly_service._is_candidate_signal(signal_name)
        )
        if candidates:
            target_ids.add(arbitration_id)
            candidate_signals_by_id[arbitration_id] = candidates

    assert target_ids, "No DBC CAN IDs containing anomaly-candidate signals were found"

    reader = BlfReader()
    decoded_messages = []
    matched_frames = 0

    for event in reader.read_events(BLF_FILE):
        arbitration_id = event.payload.get("arbitration_id")
        data_hex = event.payload.get("data")

        if arbitration_id not in target_ids or not data_hex:
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

        decoded_messages.append(decoded)
        matched_frames += 1

    assert matched_frames > 0
    assert decoded_messages

    result = anomaly_service.analyze(decoded_messages)

    print()
    print(f"Target CAN IDs: {len(target_ids)}")
    print(f"Matched target frames: {matched_frames}")
    print(f"Candidate signals observed: {result['candidate_signals']}")
    print(f"Fault findings: {result['fault_count']}")
    print(f"Warning findings: {result['warning_count']}")
    print("-" * 100)
    print("DBC candidate signals by CAN ID")
    print("-" * 100)

    for arbitration_id in sorted(candidate_signals_by_id):
        print(
            f"0x{arbitration_id:X}: "
            + ", ".join(candidate_signals_by_id[arbitration_id])
        )

    print("-" * 100)
    print("Detected anomaly findings")
    print("-" * 100)

    if not result["findings"]:
        print("No supported anomaly findings detected.")

    for index, finding in enumerate(result["findings"], start=1):
        arbitration_id = finding.get("arbitration_id")
        arbitration_id_text = (
            f"0x{arbitration_id:X}" if isinstance(arbitration_id, int) else str(arbitration_id)
        )
        print(f"[{index}] {finding['severity']} | {finding['signal']}")
        print(f"    CAN ID: {arbitration_id_text}")
        print(f"    Channel: {finding.get('channel')}")
        print(f"    Message: {finding.get('message_name')}")
        print(f"    First timestamp: {finding['first_timestamp']}")
        print(f"    Last timestamp: {finding['last_timestamp']}")
        print(f"    Occurrences: {finding['occurrences']}")
        print(f"    First abnormal value: {finding['first_value']}")
        print(f"    Last abnormal value: {finding['last_value']}")
        print(f"    Transitions: {len(finding['transitions'])}")
        print(f"    Recovered: {finding['recovered']}")

        for transition in finding["transitions"][:20]:
            print(
                f"      {transition['timestamp']}: "
                f"{transition['old_value']} -> {transition['new_value']}"
            )

        if len(finding["transitions"]) > 20:
            print(
                f"      ... {len(finding['transitions']) - 20} additional transitions omitted"
            )

    assert result["candidate_signals"] > 0
    assert isinstance(result["findings"], list)
    assert result["fault_count"] >= 0
    assert result["warning_count"] >= 0
