from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_session_service import (
    ChargingSessionService,
)
from services.dbc_decoder_service import (
    DbcDecoderService,
)


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)

DBC_FILE = Path(
    r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)


def test_charging_session_real_blf() -> None:

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

    session_service = (
        ChargingSessionService()
    )

    sessions = (
        session_service.detect_sessions(
            decoded_messages
        )
    )

    assert len(sessions) > 0

    session = sessions[0]

    print()

    print(
        f"Decoded Messages: "
        f"{len(decoded_messages)}"
    )

    print()

    print(
        f"Sessions Detected: "
        f"{len(sessions)}"
    )

    print()

    print(
        f"Start Index: "
        f"{session.start_index}"
    )

    print(
        f"End Index: "
        f"{session.end_index}"
    )

    print(
        f"Message Count: "
        f"{session.message_count}"
    )

    print()

    assert (
        session.message_count
        == len(decoded_messages)
    )