from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_diagnostic_report_service import (
    ChargingDiagnosticReportService,
)
from services.charging_root_cause_service import (
    ChargingRootCauseService,
)
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


ROOT_CAUSE_SIGNALS = [
    "HVLM_CDO_LadeerlaubnisLm",
    "HVLM_CDO_LadebereitFzg",
    "HVLM_CJ_LadebereitschaftFzg",
    "HVLM_CDO_Status_Fahrzeug",
    "HVLM_Ladevorgang_Anf",
    "HVLM_ZustandLadeablauf",
]


def test_charging_diagnostic_report_real_blf() -> None:

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

    signal_values: dict[str, str] = {}

    for signal_name in ROOT_CAUSE_SIGNALS:

        if not extractor.signal_exists(
            decoded_messages,
            signal_name,
        ):
            continue

        samples = extractor.extract(
            decoded_messages,
            signal_name,
        )

        if not samples:
            continue

        signal_values[signal_name] = str(
            samples[-1]["value"]
        )

    root_cause_service = (
        ChargingRootCauseService()
    )

    findings = (
        root_cause_service.analyze(
            signal_values
        )
    )

    report_service = (
        ChargingDiagnosticReportService()
    )

    report_path = (
        report_service.generate_report(
            signal_values=signal_values,
            findings=findings,
        )
    )

    assert report_path.exists()

    report_content = (
        report_path.read_text(
            encoding="utf-8"
        )
    )

    print()
    print(f"Report Created: {report_path}")