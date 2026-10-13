from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_case_summary_service import (
    ChargingCaseSummaryService,
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


def test_charging_case_summary_real_blf() -> None:
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

    summary_service = (
        ChargingCaseSummaryService()
    )

    summary_path = (
        summary_service.generate_summary(
            signal_values=signal_values,
            findings=findings,
        )
    )

    assert summary_path.exists()

    summary_content = (
        summary_path.read_text(
            encoding="utf-8"
        )
    )

    print()
    print(
        f"Summary Created: "
        f"{summary_path}"
    )

    print()
    print(summary_content)

    assert (
        "CHARGING CASE SUMMARY"
        in summary_content
    )

    assert (
        "EXECUTIVE SUMMARY"
        in summary_content
    )

    assert (
        "ENGINEERING CONCLUSION"
        in summary_content
    )

    assert (
        "ROOT CAUSE EVIDENCE"
        in summary_content
    )

    assert (
        "SUPPORTING SIGNALS"
        in summary_content
    )

    assert (
        "ENGINEERING ASSESSMENT"
        in summary_content
    )

    assert (
        "FINAL CONCLUSION"
        in summary_content
    )

    assert (
        "Root Cause:"
        in summary_content
    )
