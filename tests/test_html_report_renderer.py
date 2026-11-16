from pathlib import Path

from services.html_report_renderer import HtmlReportRenderer


def test_renderer_escapes_content_and_renders_status_badges() -> None:
    renderer = HtmlReportRenderer()
    html = renderer.render_page(
        title="Vehicle <Test> & Session",
        subtitle="Engineering <summary>",
        sections=[
            {
                "title": "Assessment & Status",
                "text": "Connector <not> recognized & root cause pending.",
                "rows": [
                    {"label": "VIN Status", "value": "CONFIRMED"},
                    {"label": "Root Cause", "value": "UNCONFIRMED"},
                    {"label": "Evidence", "value": "SUPPORTED_BY_MULTIPLE_TRACES"},
                    {"label": "Charging", "value": "NOT_OBSERVED"},
                ],
            }
        ],
    )

    assert "Vehicle &lt;Test&gt; &amp; Session" in html
    assert "Engineering &lt;summary&gt;" in html
    assert "Connector &lt;not&gt; recognized &amp; root cause pending." in html
    assert 'class="status status-confirmed">CONFIRMED</span>' in html
    assert 'class="status status-unconfirmed">UNCONFIRMED</span>' in html
    assert 'class="status status-supported">SUPPORTED_BY_MULTIPLE_TRACES</span>' in html
    assert 'class="status status-neutral">NOT_OBSERVED</span>' in html
    assert "<script" not in html.lower()


def test_renderer_creates_expandable_relative_detail_links() -> None:
    renderer = HtmlReportRenderer()
    links = renderer.build_manifest_links(
        [
            {
                "title": "BLF Analysis Report",
                "html": "blf/blf_analysis_report.html",
                "html_exists": True,
            },
            {
                "title": "BLF Case Summary",
                "html": "blf/blf_case_summary.html",
                "html_exists": True,
            },
            {
                "title": "Missing HTML",
                "html": "blf/missing.html",
                "html_exists": False,
            },
        ]
    )

    html = renderer.render_page(
        title="Session",
        sections=[{"title": "BLF", "links": links}],
    )

    assert "<details" in html
    assert "<summary>Detailed Reports</summary>" in html
    assert 'href="blf/blf_analysis_report.html"' in html
    assert 'href="blf/blf_case_summary.html"' in html
    assert "blf/missing.html" not in html
    assert "Missing HTML" not in html
    assert "file:///" not in html


def test_renderer_renders_back_navigation_and_escapes_link() -> None:
    renderer = HtmlReportRenderer()
    html = renderer.render_page(
        title="MF4 Case Summary",
        back_link="../test_session_summary.html?x=1&y=2",
    )

    assert "&larr; Back to Test Session Summary" in html
    assert 'href="../test_session_summary.html?x=1&amp;y=2"' in html


def test_renderer_does_not_emit_broken_detail_links() -> None:
    renderer = HtmlReportRenderer()
    links = renderer.build_manifest_links(
        [
            {
                "title": "Unavailable",
                "html": "mf4/unavailable.html",
                "html_exists": False,
            }
        ]
    )

    assert links == []
    detail_html = renderer.render_report_links(links)
    assert "href=" not in detail_html
    assert "No detailed HTML reports are available." in detail_html


def test_renderer_writes_requested_html_file(tmp_path: Path) -> None:
    renderer = HtmlReportRenderer()
    html = renderer.render_page(
        title="Test Session Summary",
        sections=[
            {
                "title": "Vehicle Identity",
                "rows": [{"label": "Status", "value": "CONFIRMED"}],
            }
        ],
    )
    output = tmp_path / "nested" / "test_session_summary.html"

    result = renderer.write_page(output, html)

    assert result == output.resolve()
    assert result.exists()
    assert result.read_text(encoding="utf-8") == html
    assert "<!doctype html>" in html.lower()
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in html
