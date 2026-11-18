from pathlib import Path
import re

ROOT = Path.cwd()


def replace(path, old, new, count=-1):
    target = ROOT / path
    source = target.read_text(encoding="utf-8")
    if old not in source:
        raise RuntimeError(f"Expected text not found in {path}: {old[:80]}")
    target.write_text(source.replace(old, new, count), encoding="utf-8")
    print(f"updated {path}")


replace("services/blf_inventory_report_service.py", "def save_report(self, inventory: BlfInventory, file_stem: str, top_count: int = 20) -> Path:", "def save_report(self, inventory: BlfInventory, file_stem: str, top_count: int = 20, run_id: str | None = None) -> Path:")
replace("services/blf_inventory_report_service.py", 'output_path = output_directory / "blf_inventory.txt"', 'suffix = f"_{run_id}" if run_id else ""\n        output_path = output_directory / f"blf_inventory{suffix}.txt"')
replace("services/blf_statistics_report_service.py", "def save_report(self, statistics: BlfStatistics, file_stem: str) -> Path:", "def save_report(self, statistics: BlfStatistics, file_stem: str, run_id: str | None = None) -> Path:")
replace("services/blf_statistics_report_service.py", 'output_path = output_directory / "blf_statistics.txt"', 'suffix = f"_{run_id}" if run_id else ""\n        output_path = output_directory / f"blf_statistics{suffix}.txt"')
replace("services/blf_vehicle_inventory_report_service.py", "charging_fault_correlation: dict | None = None,\n    ) -> Path:", "charging_fault_correlation: dict | None = None,\n        run_id: str | None = None,\n    ) -> Path:")
replace("services/blf_vehicle_inventory_report_service.py", 'analysis_path = output_dir / "blf_analysis_report.txt"\n        summary_path = output_dir / "blf_case_summary.txt"', 'suffix = f"_{run_id}" if run_id else ""\n        analysis_path = output_dir / f"blf_analysis_report{suffix}.txt"\n        summary_path = output_dir / f"blf_case_summary{suffix}.txt"')

replace("services/dlt_report_service.py", "inventory: Optional[VehicleSoftwareInventory] = None,\n    ) -> dict[str, Path]:", "inventory: Optional[VehicleSoftwareInventory] = None,\n        run_id: str | None = None,\n    ) -> dict[str, Path]:")
replace("services/dlt_report_service.py", "        reports = {\n", '        suffix = f"_{run_id}" if run_id else ""\n        reports = {\n', 1)
replace("services/pcap_report_service.py", "def generate(self, analysis: dict[str, Any]) -> dict[str, Path]:", "def generate(self, analysis: dict[str, Any], run_id: str | None = None) -> dict[str, Path]:")
replace("services/pcap_report_service.py", "        reports = {\n", '        suffix = f"_{run_id}" if run_id else ""\n        reports = {\n', 1)
for path, prefix in (("services/dlt_report_service.py", "dlt"), ("services/pcap_report_service.py", "pcap")):
    for stem in ("inventory", "statistics", "analysis_report", "case_summary"):
        replace(path, f'"{prefix}_{stem}.txt"', f'f"{prefix}_{stem}{{suffix}}.txt"')

replace("services/mf4_report_service.py", "def save_report(self, analysis: dict) -> Path:", "def save_report(self, analysis: dict, run_id: str | None = None) -> Path:")
replace("services/mf4_report_service.py", 'analysis_path = output_dir / "mf4_analysis_report.txt"\n        summary_path = output_dir / "mf4_case_summary.txt"', 'suffix = f"_{run_id}" if run_id else ""\n        analysis_path = output_dir / f"mf4_analysis_report{suffix}.txt"\n        summary_path = output_dir / f"mf4_case_summary{suffix}.txt"')

replace("services/iso15118_tls_report_service.py", "def generate(self, pcap_path, output_dir=None):", "def generate(self, pcap_path, output_dir=None, run_id: str | None = None):")
replace("services/iso15118_tls_report_service.py", "        reports = {\n", '        suffix = f"_{run_id}" if run_id else ""\n        reports = {\n', 1)
for stem in ("analysis_report", "certificate_inventory", "statistics", "case_summary"):
    replace("services/iso15118_tls_report_service.py", f'"iso15118_tls_{stem}.txt"', f'f"iso15118_tls_{stem}{{suffix}}.txt"')

replace("services/session_summary_service.py", "def save_summary(self, *, vehicle_identity=None, blf=None, dlt=None, pcap=None, mf4=None) -> Path:", "def save_summary(self, *, vehicle_identity=None, blf=None, dlt=None, pcap=None, mf4=None, run_id: str | None = None) -> Path:")
replace("services/session_summary_service.py", "output = self._output_path()", "output = self._output_path(run_id)", 1)
replace("services/session_summary_service.py", 'def _output_path(self) -> Path:\n        return Path(__file__).resolve().parent.parent / "reports" / "test_session_summary.txt"', 'def _output_path(self, run_id: str | None = None) -> Path:\n        name = f"session_summary_{run_id}.txt" if run_id else "session_summary.txt"\n        return Path(__file__).resolve().parent.parent / "reports" / name')

replace("services/session_html_report_service.py", "def save_report(self, session: dict, manifest: dict) -> Path:\n        output = self._output_path()", "def save_report(self, session: dict, manifest: dict, run_id: str | None = None) -> Path:\n        output = self._output_path(run_id)")
replace("services/session_html_report_service.py", 'def _output_path(self):\n        return Path(__file__).resolve().parent.parent / "reports" / "test_session_summary.html"', 'def _output_path(self, run_id: str | None = None):\n        name = f"session_summary_{run_id}.html" if run_id else "session_summary.html"\n        return Path(__file__).resolve().parent.parent / "reports" / name')

replace("services/detail_html_report_service.py", 'def generate_all(self, reports_root: Path = Path("reports")) -> list[Path]:', 'def generate_all(self, reports_root: Path = Path("reports"), run_id: str | None = None) -> list[Path]:')
replace("services/detail_html_report_service.py", 'for txt_path in sorted(root.rglob("*.txt")):', 'pattern = f"*_{run_id}.txt" if run_id else "*.txt"\n        for txt_path in sorted(root.rglob(pattern)):')
replace("services/detail_html_report_service.py", 'if txt_path.parent == root and txt_path.name == "test_session_summary.txt":', 'if txt_path.parent == root and txt_path.name.startswith("session_summary"):\n                continue\n            if run_id and not txt_path.stem.endswith(f"_{run_id}"):')
replace("services/detail_html_report_service.py", 'outputs.append(self.generate_one(txt_path, txt_path.with_suffix(".html"), root))', 'outputs.append(self.generate_one(txt_path, txt_path.with_suffix(".html"), root, run_id))')
replace("services/detail_html_report_service.py", "def generate_one(self, txt_path: Path, html_path: Path, reports_root: Path) -> Path:", "def generate_one(self, txt_path: Path, html_path: Path, reports_root: Path, run_id: str | None = None) -> Path:")
replace("services/detail_html_report_service.py", "back_link = self._back_link(html_path.resolve(), root)", "back_link = self._back_link(html_path.resolve(), root, run_id)")
replace("services/detail_html_report_service.py", "def _back_link(self, html_path: Path, root: Path) -> str:", "def _back_link(self, html_path: Path, root: Path, run_id: str | None = None) -> str:")
replace("services/detail_html_report_service.py", 'return (Path(*([".."] * depth)) / "test_session_summary.html").as_posix()', 'name = f"session_summary_{run_id}.html" if run_id else "session_summary.html"\n        return (Path(*([".."] * depth)) / name).as_posix()')

replace("services/session_report_manifest.py", "from pathlib import Path", "from pathlib import Path\nimport re", 1)
replace("services/session_report_manifest.py", "def build(self, reports_root: Path | None = None) -> dict:", "def build(self, reports_root: Path | None = None, run_id: str | None = None) -> dict:")
replace("services/session_report_manifest.py", '"txt": "test_session_summary.txt",\n                "html": "test_session_summary.html",', '"txt": f"session_summary_{run_id}.txt" if run_id else "session_summary.txt",\n                "html": f"session_summary_{run_id}.html" if run_id else "session_summary.html",')
replace("services/session_report_manifest.py", 'self._discover_reports(root, "blf")', 'self._discover_reports(root, "blf", run_id)')
replace("services/session_report_manifest.py", 'self._discover_reports(root, "dlt")', 'self._discover_reports(root, "dlt", run_id)')
replace("services/session_report_manifest.py", 'self._discover_reports(root, "mf4")', 'self._discover_reports(root, "mf4", run_id)')
replace("services/session_report_manifest.py", 'def _discover_reports(self, root: Path, relative_dir: str) -> list[dict]:\n        return self._discover_group(root, relative_dir, include_subdirs=False)["reports"]', 'def _discover_reports(self, root: Path, relative_dir: str, run_id: str | None = None) -> list[dict]:\n        return self._discover_group(root, relative_dir, include_subdirs=False, run_id=run_id)["reports"]')
replace("services/session_report_manifest.py", "def _discover_group(self, root: Path, relative_dir: str, include_subdirs: bool) -> dict:", "def _discover_group(self, root: Path, relative_dir: str, include_subdirs: bool, run_id: str | None = None) -> dict:")
replace("services/session_report_manifest.py", 'txt_files = directory.rglob("*.txt") if include_subdirs else directory.glob("*.txt")', 'pattern = f"*_{run_id}.txt" if run_id else "*.txt"\n            txt_files = directory.rglob(pattern) if include_subdirs else directory.glob(pattern)')
replace("services/session_report_manifest.py", "def _title(self, stem: str) -> str:\n        labels = {", 'def _title(self, stem: str) -> str:\n        stem = re.sub(r"_\d{14}$", "", stem)\n        labels = {')

replace("services/session_trace_handlers.py", "        self.dbc_file = Path(dbc_file)", "        self.dbc_file = Path(dbc_file)\n        self.run_id = None")
replace("services/session_trace_handlers.py", "    def build(self) -> dict:", "    def set_run_id(self, run_id: str) -> None:\n        self.run_id = run_id\n\n    def build(self) -> dict:")
replace("services/session_trace_handlers.py", "            blf_file.stem,\n        )", "            blf_file.stem,\n            run_id=self.run_id,\n        )", 1)
replace("services/session_trace_handlers.py", "            statistics,\n            blf_file.stem,\n        )", "            statistics,\n            blf_file.stem,\n            run_id=self.run_id,\n        )")
replace("services/session_trace_handlers.py", "            charging_fault_correlation=charging_fault_correlation,\n        )", "            charging_fault_correlation=charging_fault_correlation,\n            run_id=self.run_id,\n        )")
replace("services/session_trace_handlers.py", "DltReportService().generate(analysis)", "DltReportService().generate(analysis, run_id=self.run_id)")
replace("services/session_trace_handlers.py", "Mf4ReportService().save_report(analysis)", "Mf4ReportService().save_report(analysis, run_id=self.run_id)")

replace("services/session_processor_service.py", "from collections.abc import Callable", "from collections.abc import Callable\nfrom datetime import datetime")
replace("services/session_processor_service.py", "from pathlib import Path", "from pathlib import Path\nimport re", 1)
replace("services/session_processor_service.py", 'reports_root: Path = Path("reports"),\n    ) -> dict:', 'reports_root: Path = Path("reports"),\n        run_id: str | None = None,\n    ) -> dict:')
replace("services/session_processor_service.py", "        traces = self._normalize_discovered(discovered)", '        run_id = run_id or datetime.now().strftime("%Y%m%d%H%M%S")\n        if not re.fullmatch(r"\d{14}", run_id):\n            raise ValueError("run_id must use YYYYMMDDHHMMSS format")\n        owners = {getattr(handler, "__self__", None) for handler in self._handlers.values()}\n        for owner in owners:\n            if owner is not None and hasattr(owner, "set_run_id"):\n                owner.set_run_id(run_id)\n        traces = self._normalize_discovered(discovered)')
replace("services/session_processor_service.py", "summary_path = self._summary_service.save_summary(**session_inputs)\n        detail_html_paths = self._detail_html_service.generate_all(reports_root)\n        manifest = self._manifest_service.build(reports_root)\n        html_path = self._html_service.save_report(session_inputs, manifest)", "summary_path = self._summary_service.save_summary(**session_inputs, run_id=run_id)\n        detail_html_paths = self._detail_html_service.generate_all(reports_root, run_id=run_id)\n        manifest = self._manifest_service.build(reports_root, run_id=run_id)\n        html_path = self._html_service.save_report(session_inputs, manifest, run_id=run_id)")
replace("services/session_processor_service.py", '            "discovered": traces,', '            "run_id": run_id,\n            "discovered": traces,')

print("Timestamped report naming applied")
