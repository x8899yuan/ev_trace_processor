from pathlib import Path

from services.dbc_service import DbcService


DBC_FILE = Path(
    r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)


def test_real_dbc_load() -> None:

    service = DbcService()

    database = service.load(
        DBC_FILE
    )

    message_count = service.message_count(
        DBC_FILE
    )

    signal_count = service.signal_count(
        DBC_FILE
    )

    message_names = service.message_names(
        DBC_FILE
    )

    print()

    print(
        "DBC File:",
        DBC_FILE.name,
    )

    print()

    print(
        f"Messages: {message_count:,}"
    )

    print(
        f"Signals: {signal_count:,}"
    )

    print()

    print("First 20 Messages")
    print("-" * 50)

    for name in message_names[:20]:
        print(name)

    print()

    if database.messages:

        first_message = database.messages[0]

        print(
            "First Message Details"
        )

        print("-" * 50)

        print(
            f"Name: {first_message.name}"
        )

        print(
            f"Frame ID: 0x{first_message.frame_id:X}"
        )

        print(
            f"Length: {first_message.length}"
        )

        print()

        print("Signals")
        print("-" * 50)

        for signal in first_message.signals[:20]:
            print(signal.name)

    assert database is not None
    assert message_count > 0
    assert signal_count > 0
    assert len(message_names) > 0