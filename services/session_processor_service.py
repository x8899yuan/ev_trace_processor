from collections.abc import Callable
from datetime import datetime
from pathlib import Path
import re

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
        run_id: str | None = None,
    ) -> dict:
        run_id = run_id or datetime.now().strftime("%Y%m%d%H%M%S")
        if not re.fullmatch(r"\d{14}", run_id):
            raise ValueError("run_id must use YYYYMMDDHHMMSS format")

        reports_root = Path(reports_root)
        before = self._report_snapshot(reports_root)
        traces = self._normalize_discovered(discovered)
        supplied = [trace_type for trace_type in self.TRACE_ORDER if traces[trace_type]]

        if not supplied:
            raise ValueError("No supported traces were provided. Supply at least one BLF, DLT, PCAP, or MF4 trace.")

        missing_handlers = [trace_type for trace_type in supplied if trace_type not in self._handlers]
        if missing_handlers:
            names = ", ".join(trace_type.upper() for trace_type in missing_handlers)
            raise ValueError(f"No production handler is registered for: {names}")

        raw_results = {}
        for trace_type in supplied:
            result = self._handlers[trace_type](traces[trace_type])
            if not isinstance(result, dict):
                raise TypeError(f"{trace_type.upper()} handler must return a dictionary, got {type(result).__name__}")
            raw_results[trace_type] = result

        renamed_report_paths = self._timestamp_current_reports(reports_root, before, run_id)
        resolved_vehicle_identity = self._resolve_vehicle_identity(raw_results, vehicle_identity)
        session_inputs = self._build_session_inputs(raw_results, vehicle_identity=resolved_vehicle_identity)
        summary_path = self._summary_service.save_summary(**session_inputs, run_id=run_id)
        detail_html_paths = self._detail_html_service.generate_all(reports_root, run_id=run_id)
        manifest = self._manifest_service.build(reports_root, run_id=run_id)
        html_path = self._html_service.save_report(session_inputs, manifest, run_id=run_id)

        return {
            "run_id": run_id,
            "discovered": traces,
            "processed_trace_types": supplied,
            "raw_results": raw_results,
            "vehicle_identity": resolved_vehicle_identity,
            "session_inputs": session_inputs,
            "manifest": manifest,
            "summary_path": summary_path,
            "renamed_report_paths": renamed_report_paths,
            "detail_html_paths": detail_html_paths,
            "html_path": html_path,
        }

    def _report_snapshot(self, root: Path) -> dict[Path, tuple[int, int]]:
        if not root.exists():
            return {}
        return {path.resolve(): (path.stat().st_mtime_ns, path.stat().st_size) for path in root.rglob("*.txt")}

    def _timestamp_current_reports(self, root: Path, before: dict, run_id: str) -> list[Path]:
        if not root.exists():
            return []
        outputs = []
        for path in sorted(root.rglob("*.txt")):
            resolved = path.resolve()
            state = (path.stat().st_mtime_ns, path.stat().st_size)
            if before.get(resolved) == state:
                continue
            if path.stem.endswith(f"_{run_id}") or path.name.startswith("session_summary_"):
                outputs.append(resolved)
                continue
            destination = path.with_name(f"{path.stem}_{run_id}{path.suffix}")
            if destination.exists():
                destination.unlink()
            path.replace(destination)
            outputs.append(destination.resolve())
        return outputs

    def _resolve_vehicle_identity(self, raw_results: dict[str, dict], explicit_vehicle_identity: dict | None) -> dict | None:
        if explicit_vehicle_identity:
            return explicit_vehicle_identity
        blf_result = raw_results.get("blf") or {}
        identity = blf_result.get("vehicle_identity")
        return dict(identity) if identity else None

    def _normalize_discovered(self, discovered: dict[str, list[Path]]) -> dict[str, list[Path]]:
        return {trace_type: sorted({Path(value) for value in discovered.get(trace_type, [])}) for trace_type in self.TRACE_ORDER}

    def _build_session_inputs(self, raw_results: dict[str, dict], *, vehicle_identity: dict | None) -> dict:
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
