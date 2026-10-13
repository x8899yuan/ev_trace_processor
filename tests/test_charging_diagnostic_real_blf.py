from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_diagnostic_service import (
    ChargingDiagnosticService,
)
from services.charging_signal_extraction_service import (
    ChargingSignalExtractionService,
)
from services.dbc_decoder_service import DbcDecoderService

BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)

DBC_FILE = Path(
    r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)

TEST_SIGNAL = "NVEM_IBatt"


def test_charging_diagnostic_real_blf() -> None:

    assert BLF_FILE.exists(), (
        f"BLF file not found: {BLF_FILE}"
    )

    assert DBC_FILE.exists(), (
        f"DBC file not found: {DBC_FILE}"
    )

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

        if arbitration_id is None:
            continue

        if not data_hex:
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

    extraction_service = (
        ChargingSignalExtractionService()
    )

    samples = (
        extraction_service.extract_signal(
            decoded_messages,
            TEST_SIGNAL,
        )
    )

    diagnostic_service = (
        ChargingDiagnosticService()
    )

    analysis = (
        diagnostic_service.analyze_signal(
            TEST_SIGNAL,
            samples,
        )
    )

    abnormal_drop = (
        diagnostic_service.detect_abnormal_drop(
            samples
        )
    )

    flat_signal = (
        diagnostic_service.detect_flat_signal(
            samples
        )
    )

    print()
    print(
        f"Signal: "
        f"{analysis['signal']}"
    )

    print(
        f"Sample Count: "
        f"{analysis['sample_count']}"
    )

    print(
        f"Minimum: "
        f"{analysis['minimum']}"
    )

    print(
        f"Maximum: "
        f"{analysis['maximum']}"
    )

    print(
        f"Average: "
        f"{analysis['average']:.2f}"
    )

    print(
        f"First Value: "
        f"{analysis['first_value']}"
    )

    print(
        f"Last Value: "
        f"{analysis['last_value']}"
    )

    print(
        f"Delta: "
        f"{analysis['delta']}"
    )

    print(
        f"Trend: "
        f"{analysis['trend']}"
    )

    print(
        f"Abnormal Drop: "
        f"{abnormal_drop}"
    )

    print(
        f"Flat Signal: "
        f"{flat_signal}"
    )

    print()

    assert analysis["sample_count"] > 0
    assert analysis["minimum"] is not None
    assert analysis["maximum"] is not None
    assert analysis["trend"] in (
        "increasing",
        "decreasing",
        "stable",
    )