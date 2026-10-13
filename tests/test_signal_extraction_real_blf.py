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


def test_signal_extraction_real_blf() -> None:

    reader = BlfReader()

    events = reader.read_events(
        BLF_FILE,
        max_events=5000,
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

    assert len(decoded_messages) > 0

    extraction_service = (
        SignalExtractionService()
    )

    available_signals = (
        extraction_service.available_signals(
            decoded_messages
        )
    )

    assert len(available_signals) > 0

    signal_name = available_signals[0]

    extracted_values = (
        extraction_service.extract(
            decoded_messages,
            signal_name,
        )
    )

    print()
    print(
        f"Decoded Messages: "
        f"{len(decoded_messages)}"
    )
    print()

    print(
        f"Available Signals: "
        f"{len(available_signals)}"
    )
    print()

    print(
        f"Test Signal: "
        f"{signal_name}"
    )
    print()

    print(
        f"Extracted Values: "
        f"{len(extracted_values)}"
    )
    print()

    if extracted_values:
        print(
            extracted_values[0]
        )

    assert len(extracted_values) > 0