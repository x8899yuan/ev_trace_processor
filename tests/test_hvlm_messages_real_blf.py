from collections import defaultdict
from pathlib import Path

from readers.blf_reader import BlfReader
from services.dbc_decoder_service import DbcDecoderService
from services.signal_extraction_service import (
    SignalExtractionService,
)


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)

DBC_FILE = Path(
    r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)


def test_hvlm_messages_real_blf() -> None:

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

        if (
            arbitration_id is None
            or not data_hex
        ):
            continue

        try:

            if not decoder.message_exists(
                DBC_FILE,
                arbitration_id,
            ):
                continue

            decoded_message = (
                decoder.decode_can_message(
                    dbc_file=DBC_FILE,
                    timestamp=0.0,
                    channel=0,
                    arbitration_id=arbitration_id,
                    data=bytes.fromhex(
                        data_hex
                    ),
                )
            )

            decoded_messages.append(
                decoded_message
            )

        except Exception:
            continue

    assert decoded_messages

    extractor = SignalExtractionService()

    signal_counts = defaultdict(int)

    available_signals = (
        extractor.available_signals(
            decoded_messages
        )
    )

    for signal_name in available_signals:

        if not signal_name.startswith(
            "HVLM_"
        ):
            continue

        samples = extractor.extract(
            decoded_messages,
            signal_name,
        )

        signal_counts[
            signal_name
        ] = len(samples)

    print()
    print(
        f"Decoded Messages: "
        f"{len(decoded_messages)}"
    )

    print("=" * 100)

    sorted_signals = sorted(
        signal_counts.items(),
        key=lambda item: (
            item[1],
            item[0],
        ),
        reverse=True,
    )

    for signal_name, count in sorted_signals:

        print(
            f"{signal_name:<60} "
            f"{count}"
        )

    print("=" * 100)

    populated_signals = [
        signal_name
        for signal_name, count
        in signal_counts.items()
        if count > 0
    ]

    print(
        f"HVLM Signals Found: "
        f"{len(populated_signals)}"
    )

    assert populated_signals