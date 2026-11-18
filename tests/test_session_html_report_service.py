from pathlib import Path

import services.session_html_report_service as html_module
from services.session_html_report_service import TestSessionHtmlReportService


RUN_ID = "20261118111230"


def test_session_html_report_uses_run_id_and_current_manifest_links(tmp_path, monkeypatch):
    monkeypatch.setattr(html_module, "__file__", str(tmp_path / "services" / "session_html_report_service.py"))
    session = {"vehicle_identity": None, "blf": {"source_file": "session.blf"}, "dlt": None, "pcap": None, "mf4": None}
    manifest = {"traces": {"BLF": {"reports": [{
        "title": "Analysis Report", "html": f"blf/blf_analysis_report_{RUN_ID}.html", "html_exists": True,
    }]}}}
    output = TestSessionHtmlReportService().save_report(session, manifest, run_id=RUN_ID)
    assert output == (tmp_path / "reports" / f"session_summary_{RUN_ID}.html").resolve()
    html = output.read_text(encoding="utf-8")
    assert f'href="blf/blf_analysis_report_{RUN_ID}.html"' in html
    assert "Vehicle Test Session Engineering Summary" in html
