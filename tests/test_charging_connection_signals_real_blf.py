from collections import Counter
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


CONNECTION_SIGNALS = [
    "HVLM_Steckerstatus_A",
    "HVLM_Steckerstatus_B",
    "HVLS_Steckerstatus_SG1",
    "HVLS_Steckerstatus_SG2",
    "HVLS_PP_Status_A",
    "HVLS_PP_Status_B",
    "HVLS_CP_Status_A",
    "HVLS_CP_Status_B",
    "HVLS_PP_Latchstatus_A",
    "HVLS_PP_Latchstatus_B",
]


def test_charging_connection_signals_real_blf() -> None:

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

    print()
    print(
        f"Decoded Messages: "
        f"{len(decoded_messages)}"
    )

    print("=" * 80)

    found_signals = 0

    for signal_name in CONNECTION_SIGNALS:

        if not extractor.signal_exists(
            decoded_messages,
            signal_name,
        ):
            continue

        found_signals += 1

        samples = extractor.extract(
            decoded_messages,
            signal_name,
        )

        values = [
            str(sample["value"])
            for sample in samples
        ]

        counts = Counter(values)

        transitions = 0

        previous_value = None

        for value in values:

            if (
                previous_value is not None
                and value != previous_value
            ):
                transitions += 1

            previous_value = value

        print()
        print("=" * 80)
        print(signal_name)
        print("=" * 80)

        print(f"Sample Count: ")