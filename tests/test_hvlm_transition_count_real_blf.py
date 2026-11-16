from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_timeline_service import ChargingTimelineService
from services.dbc_decoder_service import DbcDecoderService


BLF_FILE = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")
DBC_FILE = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")
TARGET_CAN_ID = 0x272
TARGET_SIGNALS = (
    "HVLM_Ladevorgang_Anf",
    "HVLM_ZustandLadeablauf",
)


def test_hvlm_transition_count_real_blf() -> None:
    assert BLF_FILE.exists(), f"BLF file not found: {BLF_FILE}"
    assert DBC_FILE.exists(), f"DBC file not found: {DBC_FILE}"

    reader = BlfReader()
    decoder = DbcDecoderService()
    signal_samples = {signal: [] for signal in TARGET_SIGNALS}
    matched_frames = 0

    for event in reader.read_events(BLF_FILE):
        arbitration_id = event.payload.get("arbitration_id")
        data_hex = event.payload.get("data")

        if arbitration_id != TARGET_CAN_ID or not data_hex:
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

        matched_frames += 1

        for signal_name in TARGET_SIGNALS:
            if signal_name not in decoded.signals:
                continue
            signal_samples[signal_name].append(
                {
                    "timestamp": decoded.timestamp,
                    "value": decoded.signals[signal_name],
                }
            )

    assert matched_frames > 0
    assert all(signal_samples[signal] for signal in TARGET_SIGNALS)

    timeline = ChargingTimelineService().build_timeline(signal_samples)

    print()
    print(f"Target CAN ID: {hex(TARGET_CAN_ID)}")
    print(f"Matched frames: {matched_frames}")
    print(f"Timeline events: {len(timeline)}")
    print("-" * 80)

    for signal_name in TARGET_SIGNALS:
        events = [event for event in timeline if event["signal"] == signal_name]
        initial_states = [event for event in events if event["event_type"] == "INITIAL_STATE"]
        transitions = [event for event in events if event["event_type"] == "TRANSITION"]

        print(f"Signal: {signal_name}")
        print(f"Samples: {len(signal_samples[signal_name])}")
        print(f"Initial states: {len(initial_states)}")
        print(f"Transitions: {len(transitions)}")

        for event in events:
            print(
                f"  {event['timestamp']:.6f}  {event['event_type']}  "
                f"{event['old_value']} -> {event['new_value']}"
            )

        print("-" * 80)

        assert len(initial_states) == 1
        assert events[0]["event_type"] == "INITIAL_STATE"
        assert events[0]["old_value"] is None
        assert all(
            event["old_value"] != event["new_value"]
            for event in transitions
        )

    assert timeline == sorted(timeline, key=lambda event: event["timestamp"])
