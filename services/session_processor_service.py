from collections.abc import Callable
from pathlib import Path

from services.detail_html_report_service import DetailHtmlReportService
from services.session_evidence_adapter import TestSessionEvidenceAdapter
from services.session_html_report_service import TestSessionHtmlReportService
from services.session_report_manifest import TestSessionReportManifest
from services.session_summary_service import TestSessionSummaryService


class SessionProcessorService:
    TRACE_ORDER = ("blf", "dlt", "pcap", "mf4")

    def __init__(
        self,
        handlers: dict[str, Callable[[list[Path]], dict]],
        adapter: TestSessionEvidenceAdapter | None = None,
        summary_service: TestSessionSummaryService | None = None,
        manifest_service: TestSessionReportManifest | None = None,
        html_service: TestSessionHtmlReportService | None = None,
        detail_html_service: DetailHtmlReportService | None = None,
    ) -> None:
        self._handlers = dict(handlers)
        self._adapter = adapter if adapter is not None else TestSessionEvidenceAdapter()
        self._summary_service = summary_service if summary_service is not None else TestSessionSummaryService()
        self._manifest_service = manifest_service if manifest_service is not None else TestSessionReportManifest()
        self._html_service = html_service if html_service is not None else TestSessionHtmlReportService()
        self._detail_html_service = detail_html_service if detail_html_service is not None else DetailHtmlReportService()

    def process(
        self,
        discovered: dict[str, list[Path]],
        *,
        vehicle_identity: dict | None = None,
        reports_root: Path = Path("reports"),
    ) -> dict:
        traces = self._normalize_discovered(discovered)
        supplied = [trace_type for trace_type in self.TRACE_ORDER if traces[trace_type]]

        if not supplied:
            raise ValueError(
                "No supported traces were provided. Supply at least one BLF, DLT, PCAP, or MF4 trace."
            )

        missing_handlers = [trace_type for trace_type in supplied if trace_type not in self._handlers]
        if missing_handlers:
            names = ", ".join(trace_type.upper() for trace_type in missing_handlers)
            raise ValueError(f"No production handler is registered for: {names}")

        raw_results = {}
        for trace_type in supplied:
            result = self._handlers[trace_type](traces[trace_type])
            if not isinstance(result, dict):
                raise TypeError(
                    f"{trace_type.upper()} handler must return a dictionary, got {type(result).__name__}"
                )
            raw_results[trace_type] = result

        resolved_vehicle_identity = self._resolve_vehicle_identity(
            raw_results,
            vehicle_identity,
        )
        session_inputs = self._build_session_inputs(
            raw_results,
            vehicle_identity=resolved_vehicle_identity,
        )

        summary_path = self._summary_service.save_summary(**session_inputs)
        detail_html_paths = self._detail_html_service.generate_all(reports_root)
        manifest = self._manifest_service.build(reports_root)
        html_path = self._html_service.save_report(session_inputs, manifest)

        return {
            "discovered": traces,
            "processed_trace_types": supplied,
            "raw_results": raw_results,
            "vehicle_identity": resolved_vehicle_identity,
            "session_inputs": session_inputs,
            "manifest": manifest,
            "summary_path": summary_path,
            "detail_html_paths": detail_html_paths,
            "html_path": html_path,
        }

    def _resolve_vehicle_identity(
        self,
        raw_results: dict[str, dict],
        explicit_vehicle_identity: dict | None,
    ) -> dict | None:
        if explicit_vehicle_identity:
            return explicit_vehicle_identity
        blf_result = raw_results.get("blf") or {}
        identity = blf_result.get("vehicle_identity")
        return dict(identity) if identity else None

    def _normalize_discovered(
        self,
        discovered: dict[str, list[Path]],
    ) -> dict[str, list[Path]]:
        normalized = {}
        for trace_type in self.TRACE_ORDER:
            values = discovered.get(trace_type, [])
            normalized[trace_type] = sorted({Path(value) for value in values})
        return normalized

    def _build_session_inputs(
        self,
        raw_results: dict[str, dict],
        *,
        vehicle_identity: dict | None,
    ) -> dict:
        pcap = raw_results.get("pcap") or {}
        return self._adapter.build_session_inputs(
            vehicle_identity=vehicle_identity,
            blf=raw_results.get("blf"),
            dlt_analysis=raw_results.get("dlt"),
            pcap_analysis=pcap.get("analysis") if pcap else None,
            din70121=pcap.get("din70121") if pcap else None,
            iso15118_tls=pcap.get("iso15118_tls") if pcap else None,
            mf4=raw_results.get("mf4"),
        )


TestSessionProcessorService = SessionProcessorService
TestSessionProcessorService.__test__ = False
