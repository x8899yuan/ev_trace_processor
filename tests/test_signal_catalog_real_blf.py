from pathlib import Path

from readers.blf_reader import BlfReader
from services.dbc_decoder_service import DbcDecoderService
from services.signal_catalog_service import SignalCatalogService


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)

DBC_FILE = Path(
    r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)

def test_signal_catalog_real_blf() -> None:

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

        except Exception as ex:
            print(
                f"ID={arbitration_id} "
                f"Error={ex}"
            )
            continue

    assert len(decoded_messages) > 0

    service = SignalCatalogService()

    catalog = service.build_catalog(
        decoded_messages
    )

    message_names = (
        service.get_message_names(
            decoded_messages
        )
    )

    signal_names = (
        service.get_signal_names(
            decoded_messages
        )
    )

    print()

    print(
        f"Decoded Messages: "
        f"{len(decoded_messages)}"
    )

    print(
        f"Unique Messages: "
        f"{len(message_names)}"
    )

    print(
        f"Unique Signals: "
        f"{len(signal_names)}"
    )

    print()

    for message_name in sorted(
        list(catalog.keys())
    )[:10]:

        print(
            f"Message: {message_name}"
        )

        for signal_name in sorted(
            catalog[message_name]
        )[:20]:

            print(
                f"  - {signal_name}"
            )

        print()

    assert len(catalog) > 0
    assert len(message_names) > 0
    assert len(signal_names) > 0