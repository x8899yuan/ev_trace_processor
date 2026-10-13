from pathlib import Path

from readers.blf_reader import BlfReader
from services.dbc_decoder_service import (
    DbcDecoderService,
)
from services.decoded_csv_service import (
    DecodedCsvService,
)


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)

DBC_FILE = Path(
    r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)


def test_decoded_csv_real_blf() -> None:

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

    assert len(
        decoded_messages
    ) > 0

    csv_service = DecodedCsvService()

    csv_path = csv_service.save_csv(
        decoded_messages,
        (
            "VW316660436_BEUS_20251022_083710h_"
            "10242km_Trace_decoded"
        ),
    )

    print()
    print(
        f"Decoded Messages: "
        f"{len(decoded_messages)}"
    )

    print()

    print(
        f"Decoded CSV Path: "
        f"{csv_path.resolve()}"
    )

    assert csv_path.exists()

    assert (
        csv_path.stat().st_size > 0
    )