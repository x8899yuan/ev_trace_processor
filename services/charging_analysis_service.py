from pathlib import Path

from readers.blf_reader import BlfReader
from services.charging_case_summary_service import ChargingCaseSummaryService
from services.charging_diagnostic_report_service import ChargingDiagnosticReportService
from services.charging_event_detection_service import ChargingEventDetectionService
from services.charging_event_report_service import ChargingEventReportService
from services.charging_event_summary_service import ChargingEventSummaryService
from services.charging_root_cause_service import ChargingRootCauseService
from services.charging_timeline_service import ChargingTimelineService
from services.dbc_decoder_service import DbcDecoderService
from services.signal_extraction_service import SignalExtractionService


class ChargingAnalysisService:

    ROOT_CAUSE_SIGNALS = [
        "KL_Fehler_HV_Heizer",
        "HVLM_Steckerstatus_A",
        "HVLM_Steckerstatus_B",
        "STK_Stecker_Status",
        "HVLS_GBT_DcSteckerStatus",
        "HVLM_CP_State_A",
        "HVLM_CP_State_B",
        "HVLS_CP_Status_A",
        "HVLS_CP_Frequenz_A",
        "HVLS_CP_Tastgrad_A",
        "HVLM_CP_MaxStrom_A",
        "HVLM_CP_MaxStrom_B",
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
        max_events: int | None = None,
    ) -> dict:
        decoder = DbcDecoderService()
        target_ids = self._find_target_ids(decoder, dbc_file)
        reader = BlfReader()
        events = reader.read_events(blf_file, max_events=max_events)
        decoded_messages = []
        matched_frames = 0

        for event in events:
            arbitration_id = event.payload.get("arbitration_id")
            data_hex = event.payload.get("data")

            if arbitration_id not in target_ids or not data_hex:
                continue

            try:
                decoded_message = decoder.decode_can_message(
                    dbc_file=dbc_file,
                    timestamp=event.timestamp.timestamp(),
                    channel=event.payload.get("channel", 0),
                    arbitration_id=arbitration_id,
                    data=bytes.fromhex(data_hex),
                )
            except Exception:
                continue

            decoded_messages.append(decoded_message)
            matched_frames += 1

        extractor = SignalExtractionService()
        signal_samples = {}
        signal_values = {}

        for signal_name in self.ROOT_CAUSE_SIGNALS:
            if not extractor.signal_exists(decoded_messages, signal_name):
                continue

            samples = extractor.extract(decoded_messages, signal_name)
            if not samples:
                continue

            signal_samples[signal_name] = samples
            signal_values[signal_name] = str(samples[-1]["value"])

        timeline = ChargingTimelineService().build_timeline(signal_samples)
        detected_events = ChargingEventDetectionService().detect_events(timeline)
        event_report = ChargingEventReportService().generate_report(detected_events)
        event_summary_service = ChargingEventSummaryService()
        event_summary_text = event_summary_service.generate_summary(detected_events)
        event_summary_path = Path("reports/charging/charging_event_summary.txt")
        event_summary_service.save_summary(event_summary_text, event_summary_path)
        findings = ChargingRootCauseService().analyze(signal_values)

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

        diagnostic_report = ChargingDiagnosticReportService().generate(
            diagnostics=[],
            root_causes=root_causes,
            supporting_signals=signal_values,
            engineering_conclusions=engineering_conclusions,
            recommendations=None,
        )
        case_summary = ChargingCaseSummaryService().generate_summary(
            signal_values,
            findings,
        )

        initial_states = [
            entry for entry in timeline if entry["event_type"] == "INITIAL_STATE"
        ]
        transitions = [
            entry for entry in timeline if entry["event_type"] == "TRANSITION"
        ]
        unavailable_signals = [
            signal
            for signal in self.ROOT_CAUSE_SIGNALS
            if signal not in signal_samples
        ]

        return {
            "decoded_messages": len(decoded_messages),
            "_decoded_message_objects": decoded_messages,
            "_signal_samples": signal_samples,
            "matched_frames": matched_frames,
            "target_can_ids": sorted(target_ids),
            "signal_values": signal_values,
            "available_signals": sorted(signal_samples),
            "unavailable_signals": unavailable_signals,
            "timeline": timeline,
            "timeline_entries": len(timeline),
            "initial_state_entries": len(initial_states),
            "transition_entries": len(transitions),
            "events_detected": len(detected_events),
            "findings": findings,
            "event_report": event_report,
            "event_summary": event_summary_path,
            "diagnostic_report": diagnostic_report,
            "case_summary": case_summary,
        }

    def _find_target_ids(
        self,
        decoder: DbcDecoderService,
        dbc_file: Path,
    ) -> set[int]:
        target_ids = set()
        target_signals = set(self.ROOT_CAUSE_SIGNALS)

        for arbitration_id in range(0x800):
            signal_names = decoder.message_signal_names(
                dbc_file,
                arbitration_id,
            )

            if target_signals.intersection(signal_names):
                target_ids.add(arbitration_id)

        return target_ids
