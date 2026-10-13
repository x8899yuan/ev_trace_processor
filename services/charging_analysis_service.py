from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_case_summary_service import (
    ChargingCaseSummaryService,
)
from services.charging_diagnostic_report_service import (
    ChargingDiagnosticReportService,
)
from services.charging_event_detection_service import (
    ChargingEventDetectionService,
)
from services.charging_event_report_service import (
    ChargingEventReportService,
)
from services.charging_event_summary_service import (
    ChargingEventSummaryService,
)
from services.charging_root_cause_service import (
    ChargingRootCauseService,
)
from services.charging_timeline_service import (
    ChargingTimelineService,
)
from services.dbc_decoder_service import (
    DbcDecoderService,
)
from services.signal_extraction_service import (
    SignalExtractionService,
)


class ChargingAnalysisService:

    ROOT_CAUSE_SIGNALS = [
        "HVLM_CDO_LadeerlaubnisLm",
        "HVLM_CDO_LadebereitFzg",
        "HVLM_CJ_LadebereitschaftFzg",
        "HVLM_CDO_Status_Fahrzeug",
        "HVLM_Ladevorgang_Anf",
        "HVLM_ZustandLadeablauf",
    ]

    def analyze(
        self,
        blf_file: Path,
        dbc_file: Path,
        max_events: int = 10000,
    ) -> dict:

        reader = BlfReader()

        events = reader.read_events(
            blf_file,
            max_events=max_events,
        )

        decoder = DbcDecoderService()

        decoded_messages = []

        for event in events:

            arbitration_id = (
                event.payload.get(
                    "arbitration_id"
                )
            )

            data_hex = (
                event.payload.get(
                    "data"
                )
            )

            if (
                arbitration_id is None
                or not data_hex
            ):
                continue

            try:

                if not decoder.message_exists(
                    dbc_file,
                    arbitration_id,
                ):
                    continue

                decoded_message = (
                    decoder.decode_can_message(
                        dbc_file=dbc_file,
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

        extractor = (
            SignalExtractionService()
        )

        signal_samples = {}

        signal_values = {}

        for signal_name in (
            self.ROOT_CAUSE_SIGNALS
        ):

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

            signal_samples[
                signal_name
            ] = samples

            signal_values[
                signal_name
            ] = str(
                samples[-1]["value"]
            )

        timeline_service = (
            ChargingTimelineService()
        )

        timeline = (
            timeline_service.build_timeline(
                signal_samples
            )
        )

        event_detection_service = (
            ChargingEventDetectionService()
        )

        detected_events = (
            event_detection_service.detect_events(
                timeline
            )
        )

        event_report_service = (
            ChargingEventReportService()
        )

        event_report = (
            event_report_service.generate_report(
                detected_events
            )
        )

        event_summary_service = (
            ChargingEventSummaryService()
        )

        event_summary_text = (
            event_summary_service.generate_summary(
                detected_events
            )
        )

        event_summary_path = Path(
            "reports/charging/charging_event_summary.txt"
        )

        event_summary_service.save_summary(
            event_summary_text,
            event_summary_path,
        )

        root_cause_service = (
            ChargingRootCauseService()
        )

        findings = (
            root_cause_service.analyze(
                signal_values
            )
        )

        diagnostic_report_service = (
            ChargingDiagnosticReportService()
        )

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

        diagnostic_report = (
            diagnostic_report_service.generate(
                diagnostics=[],
                root_causes=root_causes,
                supporting_signals=signal_values,
                engineering_conclusions=engineering_conclusions,
                recommendations=None,
            )
        )

        case_summary_service = (
            ChargingCaseSummaryService()
        )

        case_summary = (
            case_summary_service.generate_summary(
                signal_values,
                findings,
            )
        )

        return {
            "decoded_messages":
                len(decoded_messages),
            "signal_values":
                signal_values,
            "timeline_entries":
                len(timeline),
            "events_detected":
                len(detected_events),
            "findings":
                findings,
            "event_report":
                event_report,
            "event_summary":
                event_summary_path,
            "diagnostic_report":
                diagnostic_report,
            "case_summary":
                case_summary,
        }