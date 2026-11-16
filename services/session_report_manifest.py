from pathlib import Path


class TestSessionReportManifest:
    def build(self, reports_root: Path | None = None) -> dict:
        root = Path(reports_root) if reports_root is not None else Path("reports")
        return {
            "session": {
                "title": "Vehicle Test Session Engineering Summary",
                "txt": "test_session_summary.txt",
                "html": "test_session_summary.html",
            },
            "traces": {
                "BLF": {"title": "BLF", "reports": self._discover_reports(root, "blf")},
                "DLT": {"title": "DLT", "reports": self._discover_reports(root, "dlt")},
                "PCAP": {
                    "title": "PCAP / V2G",
                    "reports": self._pcap_navigation(root),
                },
                "MF4": {"title": "MF4", "reports": self._discover_reports(root, "mf4")},
            },
        }

    def _pcap_navigation(self, root: Path) -> list[dict]:
        reports = []
        generic = self._first_existing_html(root, [
            "pcap/pcap_analysis_report.html",
            "pcap/pcap_case_summary.html",
        ])
        reports.extend(generic)
        din_index = root / "pcap" / "din70121" / "index.html"
        tls_index = root / "pcap" / "iso15118" / "index.html"
        reports.extend([
            self._report(root, "DIN 70121 Detailed Reports", "", "pcap/din70121/index.html"),
            self._report(root, "ISO 15118 / TLS Detailed Reports", "", "pcap/iso15118/index.html"),
        ])
        reports[-2]["html_exists"] = din_index.exists()
        reports[-1]["html_exists"] = tls_index.exists()
        return reports

    def _first_existing_html(self, root: Path, paths: list[str]) -> list[dict]:
        reports = []
        for relative in paths:
            path = root / relative
            if path.exists():
                reports.append({
                    "title": self._title(path.stem),
                    "txt": "",
                    "html": relative,
                    "txt_exists": False,
                    "html_exists": True,
                })
        return reports

    def _discover_reports(self, root: Path, relative_dir: str) -> list[dict]:
        return self._discover_group(root, relative_dir, include_subdirs=False)["reports"]

    def _discover_group(self, root: Path, relative_dir: str, include_subdirs: bool) -> dict:
        directory = root / Path(relative_dir)
        reports = []
        if directory.exists():
            txt_files = directory.rglob("*.txt") if include_subdirs else directory.glob("*.txt")
            for txt_path in sorted(txt_files):
                rel_txt = txt_path.relative_to(root).as_posix()
                html_path = txt_path.with_suffix(".html")
                rel_html = html_path.relative_to(root).as_posix()
                reports.append(self._report(root, self._title(txt_path.stem), rel_txt, rel_html))
        return {"directory": relative_dir, "reports": reports}

    def _report(self, root: Path, title: str, txt: str, html: str) -> dict:
        return {
            "title": title,
            "txt": txt,
            "html": html,
            "txt_exists": (root / txt).exists(),
            "html_exists": (root / html).exists(),
        }

    def _title(self, stem: str) -> str:
        labels = {
            "blf_analysis_report": "Analysis Report",
            "blf_case_summary": "Case Summary",
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
