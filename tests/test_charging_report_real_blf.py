from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_diagnostic_service import ChargingDiagnosticService
from services.charging_report_service import ChargingReportService
from services.dbc_decoder_service import DbcDecoderService
from services.signal_extraction_service import SignalExtractionService


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)

DBC_FILE = Path(
    r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
)


def test_charging_report_real_blf() -> None:

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

    extractor = SignalExtractionService()

    signal_name = "NVEM_Ladezustand"

    assert extractor.signal_exists(
        decoded_messages,
        signal_name,
    )

    raw_samples = extractor.extract(
        decoded_messages,
        signal_name,
    )

    assert len(raw_samples) > 0

    samples = [
        (
            sample["timestamp"],
            float(sample["value"]),
        )
        for sample in raw_samples
    ]

    diagnostic_service = (
        ChargingDiagnosticService()
    )

    analysis = (
        diagnostic_service.analyze_signal(
            signal_name=signal_name,
            samples=samples,
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

    report_service = (
        ChargingReportService()
    )

    report_path = (
        report_service.generate_report(
            analysis=analysis,
            abnormal_drop=abnormal_drop,
            flat_signal=flat_signal,
        )
    )

    assert report_path.exists()

    report_content = (
        report_path.read_text(
            encoding="utf-8"
        )
    )

    print()

    print(
        f"Decoded Messages: "
        f"{len(decoded_messages)}"
    )

    print(
        f"Signal Name: "
        f"{signal_name}"
    )

    print(
        f"Samples Found: "
        f"{len(samples)}"
    )

    print(
        f"Report Created: "
        f"{report_path}"
    )

    print()

    print(report_content)

    assert (
        "CHARGING DIAGNOSTIC REPORT"
        in report_content
    )

    assert (
        signal_name
        in report_content
    )