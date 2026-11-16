from html import escape
from pathlib import Path


class HtmlReportRenderer:
    STATUS_CLASSES = {
        "CONFIRMED": "status status-confirmed",
        "OBSERVED": "status status-observed",
        "SUPPORTED_BY_MULTIPLE_TRACES": "status status-supported",
        "SUPPORTED BY MULTIPLE TRACES": "status status-supported",
        "UNCONFIRMED": "status status-unconfirmed",
        "FAULT": "status status-fault",
        "NOT_OBSERVED": "status status-neutral",
        "NOT OBSERVED": "status status-neutral",
        "NOT_RECOGNIZED": "status status-neutral",
        "NOT_ESTABLISHED": "status status-neutral",
        "INDETERMINATE": "status status-indeterminate",
        "NOT SUPPLIED": "status status-indeterminate",
    }

    def render_page(
        self,
        *,
        title: str,
        subtitle: str | None = None,
        sections: list[dict] | None = None,
        back_link: str | None = None,
        back_label: str = "Back to Test Session Summary",
    ) -> str:
        content = []
        if back_link:
            content.append(
                f'<a class="back-link" href="{escape(back_link, quote=True)}">&larr; {escape(back_label)}</a>'
            )
        content.append(f"<h1>{escape(title)}</h1>")
        if subtitle:
            content.append(f'<p class="subtitle">{escape(subtitle)}</p>')
        for section in sections or []:
            content.append(self.render_section(section))
        return self._document(title, "\n".join(content))

    def render_section(self, section: dict) -> str:
        title = escape(str(section.get("title", "Section")))
        body = []
        text = section.get("text")
        if text:
            body.append(f"<p>{escape(str(text))}</p>")
        rows = section.get("rows", [])
        if rows:
            body.append('<dl class="kv-list">')
            for row in rows:
                label = escape(str(row.get("label", "")))
                value = str(row.get("value", ""))
                body.append(f"<dt>{label}</dt><dd>{self.render_status(value)}</dd>")
            body.append("</dl>")
        items = section.get("items", [])
        if items:
            body.append("<ul>")
            for item in items:
                body.append(f"<li>{escape(str(item))}</li>")
            body.append("</ul>")
        links = section.get("links", [])
        if links:
            body.append(self.render_report_links(links))
        return f'<section class="report-section"><h2>{title}</h2>{"".join(body)}</section>'

    def render_report_links(self, links: list[dict]) -> str:
        available = [item for item in links if item.get("href")]
        if not available:
            return '<p class="muted">No detailed HTML reports are available.</p>'
        rows = ['<details class="details"><summary>Detailed Reports</summary><ul class="report-links">']
        for item in available:
            title = escape(str(item.get("title", "Report")))
            href = escape(str(item["href"]), quote=True)
            rows.append(f'<li><a href="{href}">{title}</a></li>')
        rows.append("</ul></details>")
        return "".join(rows)

    def render_status(self, value: str) -> str:
        text = escape(str(value))
        status_class = self.STATUS_CLASSES.get(str(value).upper())
        if status_class:
            return f'<span class="{status_class}">{text}</span>'
        return text

    def write_page(self, output_path: Path, html: str) -> Path:
        output_path = Path(output_path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        return output_path

    def build_manifest_links(self, entries: list[dict]) -> list[dict]:
        links = []
        for entry in entries:
            if not entry.get("html_exists"):
                continue
            links.append({"title": entry.get("title", "Report"), "href": entry.get("html")})
        return links

    def _document(self, title: str, body: str) -> str:
        return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<style>
:root {{ color-scheme: light dark; --bg:#f4f7fb; --panel:#fff; --text:#172033; --muted:#657086; --border:#d9e1ec; --link:#075fbd; --green:#157347; --blue:#0b5ed7; --amber:#946200; --red:#b42318; --gray:#596273; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#111722; --panel:#1a2230; --text:#eef3fa; --muted:#a8b3c4; --border:#344154; --link:#79b8ff; --green:#70d49b; --blue:#75a7ff; --amber:#f1c56a; --red:#ff8b82; --gray:#b1bac8; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:15px/1.55 "Segoe UI",Arial,sans-serif; }}
main {{ max-width:1080px; margin:0 auto; padding:32px 20px 64px; }}
h1 {{ margin:8px 0 4px; font-size:30px; }}
h2 {{ margin:0 0 14px; font-size:19px; }}
a {{ color:var(--link); }}
.subtitle,.muted {{ color:var(--muted); }}
.back-link {{ display:inline-block; margin-bottom:12px; text-decoration:none; }}
.report-section {{ margin-top:18px; padding:20px; background:var(--panel); border:1px solid var(--border); border-radius:12px; }}
.kv-list {{ display:grid; grid-template-columns:minmax(190px, 34%) 1fr; gap:9px 18px; margin:0; }}
.kv-list dt {{ color:var(--muted); font-weight:600; }}
.kv-list dd {{ margin:0; }}
.status {{ display:inline-block; padding:2px 8px; border:1px solid currentColor; border-radius:999px; font-size:12px; font-weight:700; }}
.status-confirmed,.status-supported {{ color:var(--green); }}
.status-observed {{ color:var(--blue); }}
.status-unconfirmed {{ color:var(--amber); }}
.status-fault {{ color:var(--red); }}
.status-neutral,.status-indeterminate {{ color:var(--gray); }}
.details {{ margin-top:14px; border-top:1px solid var(--border); padding-top:12px; }}
.details summary {{ cursor:pointer; font-weight:700; }}
.report-links {{ margin-bottom:0; }}
@media (max-width:600px) {{ .kv-list {{ grid-template-columns:1fr; gap:2px; }} .kv-list dd {{ margin-bottom:9px; }} main {{ padding:20px 12px 40px; }} }}
</style>
</head>
<body><main>{body}</main></body>
</html>'''
