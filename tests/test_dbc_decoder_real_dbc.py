from pathlib import Path

from services.dbc_decoder_service import (
    DbcDecoderService,
)


DBC_FILE = Path(
    r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)


def test_real_dbc_decode() -> None:

    decoder = DbcDecoderService()

    arbitration_id = 0x40

    data = bytes(
        [
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]
    )

    assert decoder.message_exists(
        DBC_FILE,
        arbitration_id,
    )

    message_name = decoder.message_name(
        DBC_FILE,
        arbitration_id,
    )

    print()

    print(
        f"Message Name: "
        f"{message_name}"
    )

    decoded = decoder.decode_message(
        DBC_FILE,
        arbitration_id,
        data,
    )

    print()

    print(
        f"Decoded Signal Count: "
        f"{len(decoded)}"
    )

    print()

    print(
        "First 20 Signals"
    )

    print("-" * 50)

    for signal_name, value in list(
        decoded.items()
    )[:20]:

        print(
            f"{signal_name}: "
            f"{value}"
        )

    print()

    assert decoded
    assert len(decoded) > 0
    assert message_name == "Airbag_01"