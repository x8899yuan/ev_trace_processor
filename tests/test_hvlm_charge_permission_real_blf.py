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


PERMISSION_SIGNALS = [
    "HVLM_CDO_LadebereitFzg",
    "HVLM_CDO_LadeerlaubnisLm",
    "HVLM_CDO_Status_Fahrzeug",
    "HVLM_CDO_LadenBeendenAnfFzg",
    "HVLM_CJ_LadebereitschaftFzg",
    "HVLM_CJ_VerbindungAnf",
    "HVLM_CJ_StatusProtokollVerh",
]


def test_hvlm_charge_permission_real_blf() -> None:

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

    print("=" * 100)

    found_signals = 0

    for signal_name in PERMISSION_SIGNALS:

        if not extractor.signal_exists(
            decoded_messages,
            signal_name,
        ):
            print()
            print(
                f"{signal_name}: NOT FOUND"
            )
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
        print("=" * 100)
        print(signal_name)
        print("=" * 100)

        print(
            f"Sample Count: "
            f"{len(samples)}"
        )

        print(
            f"Unique Values: "
            f"{len(counts)}"
        )

        print(
            f"Transitions: "
            f"{transitions}"
        )

        print()

        for value, count in sorted(
            counts.items()
        ):
            print(
                f"{value}: {count}"
            )

    print