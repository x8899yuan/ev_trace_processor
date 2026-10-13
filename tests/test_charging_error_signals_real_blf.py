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


ERROR_SIGNALS = [
    "HVLE_OBG_Fehlerstatus",
    "HVLM_CDO_Fehler_Fahrzeug",
    "HVLM_CDO_Fehler_HVBatSpgDiffFzg",
    "HVLM_CDO_Fehler_HVBatUeberspgFzg",
    "HVLM_CDO_Fehler_HVBatUebertemp",
    "HVLM_CDO_Fehler_HVBatUnterspFzg",
    "HVLM_CDO_Fehler_HVStromDiffFzg",
    "HVLM_CP_Fehlerzustand_A",
    "HVLM_CP_Fehlerzustand_B",
    "HVLS_CP_Fehlerstatus_A",
    "HVLS_CP_Fehlerstatus_B",
    "HVLS_PP_Fehlerstatus_A",
    "HVLS_PP_Fehlerstatus_B",
    "HVLX_PlcFehlerstatus",
]


def test_charging_error_signals_real_blf() -> None:

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

    for signal_name in ERROR_SIGNALS:

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

        print()
        print("=" * 80)
        print(signal_name)
        print("=" * 80)

        print(
            f"Sample Count: "
            f"{len(samples)}"
        )

        print(
            f"Unique Values: "
            f"{len(counts)}"
        )

        print()

        for value, count in sorted(
            counts.items()
        ):
            print(
                f"{value}: {count}"
            )

    print()
    print(
        f"Error Signals Found: "
        f"{found_signals}"
    )

    assert found_signals > 0