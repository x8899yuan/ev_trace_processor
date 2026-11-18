from pathlib import Path
import re


class TestSessionReportManifest:
    def build(self, reports_root: Path | None = None, run_id: str | None = None) -> dict:
        root = Path(reports_root) if reports_root is not None else Path("reports")
        suffix = f"_{run_id}" if run_id else ""
        return {
            "session": {
                "title": "Vehicle Test Session Engineering Summary",
                "txt": f"session_summary{suffix}.txt",
                "html": f"session_summary{suffix}.html",
            },
            "traces": {
                "BLF": {"title": "BLF", "reports": self._discover_reports(root, "blf", run_id)},
                "DLT": {"title": "DLT", "reports": self._discover_reports(root, "dlt", run_id)},
                "PCAP": {"title": "PCAP / V2G", "reports": self._pcap_navigation(root, run_id)},
                "MF4": {"title": "MF4", "reports": self._discover_reports(root, "mf4", run_id)},
            },
        }

    def _pcap_navigation(self, root: Path, run_id: str | None = None) -> list[dict]:
        reports = self._discover_reports(root, "pcap", run_id, include_subdirs=True)
        din_index = root / "pcap" / "din70121" / "index.html"
        tls_index = root / "pcap" / "iso15118" / "index.html"
        if din_index.exists():
            reports.append(self._html_only_report(root, "DIN 70121 Detailed Reports", din_index))
        if tls_index.exists():
            reports.append(self._html_only_report(root, "ISO 15118 / TLS Detailed Reports", tls_index))
        return self._deduplicate(reports)

    def _discover_reports(self, root: Path, relative_dir: str, run_id: str | None, include_subdirs: bool = False) -> list[dict]:
        directory = root / relative_dir
        if not directory.exists():
            return []
        pattern = f"*_{run_id}.txt" if run_id else "*.txt"
        paths = directory.rglob(pattern) if include_subdirs else directory.glob(pattern)
        reports = []
        for txt_path in sorted(paths):
            html_path = txt_path.with_suffix(".html")
            reports.append(self._report(root, self._title(txt_path.stem), txt_path, html_path))
        return reports

    def _html_only_report(self, root: Path, title: str, html_path: Path) -> dict:
        return {
            "title": title,
            "txt": "",
            "html": html_path.relative_to(root).as_posix(),
            "txt_exists": False,
            "html_exists": html_path.exists(),
        }

    def _report(self, root: Path, title: str, txt_path: Path, html_path: Path) -> dict:
        return {
            "title": title,
            "txt": txt_path.relative_to(root).as_posix(),
            "html": html_path.relative_to(root).as_posix(),
            "txt_exists": txt_path.exists(),
            "html_exists": html_path.exists(),
        }

    def _deduplicate(self, reports: list[dict]) -> list[dict]:
        seen = set()
        result = []
        for report in reports:
            key = report.get("html") or report.get("txt")
            if key in seen:
                continue
            seen.add(key)
            result.append(report)
        return result

    def _title(self, stem: str) -> str:
        stem = re.sub(r"_\d{14}$", "", stem)
        labels = {
            "blf_analysis_report": "Analysis Report",
            "blf_case_summary": "Case Summary",
            "blf_inventory": "Inventory",
            "blf_statistics": "Statistics",
            "dlt_analysis_report": "Analysis Report",
            "dlt_case_summary": "Case Summary",
            "dlt_inventory": "Inventory",
            "dlt_statistics": "Statistics",
            "mf4_analysis_report": "Analysis Report",
            "mf4_case_summary": "Case Summary",
            "pcap_analysis_report": "Analysis Report",
            "pcap_case_summary": "Case Summary",
            "pcap_inventory": "Inventory",
            "pcap_statistics": "Statistics",
            "din70121_analysis_report": "DIN 70121 Analysis",
            "din70121_case_summary": "DIN 70121 Case Summary",
            "iso15118_tls_analysis_report": "ISO 15118 / TLS Analysis",
            "iso15118_tls_case_summary": "ISO 15118 / TLS Case Summary",
            "iso15118_tls_certificate_inventory": "Certificate Inventory",
        }
        return labels.get(stem, stem.replace("_", " ").replace("-", " ").strip().title())
