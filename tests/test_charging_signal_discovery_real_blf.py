from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_signal_discovery_service import (
    ChargingSignalDiscoveryService,
)
from services.dbc_decoder_service import DbcDecoderService

BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)

DBC_FILE = Path(
    r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)


def test_charging_signal_discovery_real_blf() -> None:
    assert BLF_FILE.exists(), f"BLF file not found: {BLF_FILE}"
    assert DBC_FILE.exists(), f"DBC file not found: {DBC_FILE}"

    reader = BlfReader()

    events = reader.read_events(
        BLF_FILE,
        max_events=10000,
    )

    decoder = DbcDecoderService()
    decoded_messages = []

    for event in events:
        arbitration_id = event.payload.get(
            "arbitration_id"
        )

        data_hex = event.payload.get(
            "data"
        )

        if arbitration_id is None or not data_hex:
            continue

        try:
            if not decoder.message_exists(
                DBC_FILE,
                arbitration_id,
            ):
                continue

            decoded_message = decoder.decode_can_message(
                dbc_file=DBC_FILE,
                timestamp=0.0,
                channel=0,
                arbitration_id=arbitration_id,
                data=bytes.fromhex(data_hex),
            )

            decoded_messages.append(
                decoded_message
            )

        except Exception:
            continue

    discovery_service = (
        ChargingSignalDiscoveryService()
    )

    results = discovery_service.discover(
        decoded_messages
    )

    charging_signals = results[
        "charging_signals"
    ]

    print()
    print(
        f"Decoded Messages: "
        f"{len(decoded_messages)}"
    )
    print(
        f"Total Signals: "
        f"{results['total_signals']}"
    )
    print(
        f"Charging Signals Found: "
        f"{results['charging_signal_count']}"
    )
    print("-" * 60)

    for signal_name in charging_signals:
        print(signal_name)

    print("-" * 60)

    assert decoded_messages
    assert results["total_signals"] > 0
    assert (
        results["charging_signal_count"]
        == len(charging_signals)
    )
    assert charging_signals