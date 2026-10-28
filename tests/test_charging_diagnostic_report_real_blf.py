from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_diagnostic_report_service import ChargingDiagnosticReportService
from services.charging_root_cause_service import ChargingRootCauseService
from services.dbc_decoder_service import DbcDecoderService
from services.signal_extraction_service import SignalExtractionService


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ROOT_CAUSE_SIGNALS = [
    "HVLM_CDO_LadeerlaubnisLm",
    "HVLM_CDO_LadebereitFzg",
    "HVLM_CJ_LadebereitschaftFzg",
    "HVLM_CDO_Status_Fahrzeug",
    "HVLM_Ladevorgang_Anf",
    "HVLM_ZustandLadeablauf",
]


def find_file(file_name: str) -> Path:
    matches = list(PROJECT_ROOT.rglob(file_name))
    assert matches, f"File not found: {file_name}"
    return matches[0]


def test_charging_diagnostic_report_real_blf() -> None:
    blf_file = find_file(
        "VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
    )
    dbc_file = find_file(
        "E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
    )

    reader = BlfReader()
    events = reader.read_events(blf_file, max_events=10000)

    decoder = DbcDecoderService()
    decoded_messages = []

    for event in events:
        arbitration_id = event.payload.get("arbitration_id")
        data_hex = event.payload.get("data")

        if arbitration_id is None or not data_hex:
            continue

        try:
            if not decoder.message_exists(dbc_file, arbitration_id):
                continue

            decoded_message = decoder.decode_can_message(
                dbc_file=dbc_file,
                timestamp=event.timestamp.timestamp(),
                channel=event.payload.get("channel", 0),
                arbitration_id=arbitration_id,
                data=bytes.fromhex(data_hex),
            )
            decoded_messages.append(decoded_message)
        except Exception:
            continue

    assert decoded_messages
    assert any(message.timestamp != 0.0 for message in decoded_messages)

    extractor = SignalExtractionService()
    signal_values: dict[str, str] = {}

    for signal_name in ROOT_CAUSE_SIGNALS:
        if not extractor.signal_exists(decoded_messages, signal_name):
            continue

        samples = extractor.extract(decoded_messages, signal_name)
        if not samples:
            continue

        signal_values[signal_name] = str(samples[-1]["value"])

    assert signal_values

    root_cause_service = ChargingRootCauseService()
    findings = root_cause_service.analyze(signal_values)

    engineering_conclusions = [
        finding
        for finding in findings
        if finding.startswith(
            (
                "Root Cause:",
                "Contributing Factor:",
                "Observation:",
            )
        )
    ]

    root_causes = [
        finding
        for finding in findings
        if not finding.startswith(
            (
                "Root Cause:",
                "Contributing Factor:",
                "Observation:",
            )
        )
    ]

    report_service = ChargingDiagnosticReportService()
    report = report_service.generate(
        diagnostics=[],
        root_causes=root_causes,
        supporting_signals=signal_values,
        engineering_conclusions=engineering_conclusions,
        recommendations=None,
    )

    assert isinstance(report, str)
    assert report
    assert "CHARGING DIAGNOSTIC REPORT" in report
    assert "ENGINEERING CONCLUSION" in report
    assert "ROOT CAUSE SUMMARY" in report
    assert "SUPPORTING SIGNALS" in report
    assert "DIAGNOSTIC ASSESSMENT" in report

    for signal_name, signal_value in signal_values.items():
        assert f"{signal_name}: {signal_value}" in report
