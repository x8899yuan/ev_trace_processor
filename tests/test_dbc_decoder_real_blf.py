from pathlib import Path

from models.decoded_can_message import (
    DecodedCanMessage,
)
from readers.blf_reader import BlfReader
from services.dbc_decoder_service import (
    DbcDecoderService,
)


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)

DBC_FILE = Path(
    r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)


def test_real_blf_decode() -> None:

    reader = BlfReader()

    events = reader.read_events(
        BLF_FILE,
        max_events=1000,
    )

    decoder = DbcDecoderService()

    decoded_count = 0

    print()
    print("Searching first 1000 BLF events")
    print("-" * 50)

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

            decoded = (
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

            assert isinstance(
                decoded,
                DecodedCanMessage,
            )

            print()

            print(
                f"CAN ID: "
                f"0x{decoded.can_id:X}"
            )

            print(
                f"Message: "
                f"{decoded.message_name}"
            )

            print(
                f"Signals: "
                f"{len(decoded.signals)}"
            )

            print("-" * 50)

            for signal_name, value in list(
                decoded.signals.items()
            )[:10]:

                print(
                    f"{signal_name}: "
                    f"{value}"
                )

            decoded_count += 1

            break

        except Exception as exc:

            print(
                f"Decode failed for "
                f"0x{arbitration_id:X}: "
                f"{exc}"
            )

    print()

    print(
        f"Successfully Decoded: "
        f"{decoded_count}"
    )

    print()

    assert decoded_count > 0