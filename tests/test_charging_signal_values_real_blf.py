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


SIGNALS_TO_CHECK = [
    "HVK_Ladebereit",
    "HVLM_Ladevorgang_Anf",
    "HVLM_ZustandLadeablauf",
    "HVLM_CJ_IstSOC",
    "HVLM_CJ_Lademodus",
    "HVLE_OBG_DC_IstStrom",
    "HVLE_OBG_ACDC_IstLeistung",
    "HVLE_IstSpannung_HV",
    "NVEM_IBatt",
]


def test_charging_signal_values_real_blf() -> None:

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

    for signal_name in SIGNALS_TO_CHECK:

        if not extractor.signal_exists(
            decoded_messages,
            signal_name,
        ):
            print(
                f"\nSignal: {signal_name}"
            )
            print("NOT FOUND")
            continue

        samples = extractor.extract(
            decoded_messages,
            signal_name,
        )

        values = []

        for sample in samples:

            value = sample["value"]

            try:
                values.append(
                    float(value)
                )
            except (
                TypeError,
                ValueError,
            ):
                pass

        print(
            f"\nSignal: {signal_name}"
        )

        print(
            f"Samples: {len(samples)}"
        )

        if values:

            print(
                f"Min: {min(values)}"
            )

            print(
                f"Max: {max(values)}"
            )

            print(
                f"First: {values[0]}"
            )

            print(
                f"Last: {values[-1]}"
            )

        else:

            unique_values = sorted(
                {
                    str(
                        sample["value"]
                    )
                    for sample in samples
                }
            )

            print(
                f"Unique Values: "
                f"{unique_values[:20]}"
            )

        found_signals += 1

    print()
    print(
        f"Signals Found: "
        f"{found_signals}"
    )

    assert found_signals > 0