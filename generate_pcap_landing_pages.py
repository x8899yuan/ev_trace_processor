from html import escape
from pathlib import Path


REPORTS = Path("reports")


def build(protocol_dir: Path, title: str) -> Path:
    groups = []
    for capture_dir in sorted(path for path in protocol_dir.iterdir() if path.is_dir()):
        links = []
        for html in sorted(capture_dir.glob("*.html")):
            links.append((html.stem.replace("_", " ").title(), html.relative_to(protocol_dir).as_posix()))
        if links:
            groups.append((capture_dir.name, links))
    sections = []
    for capture, links in groups:
        items = "".join(f'<li><a href="{escape(href, quote=True)}">{escape(label)}</a></li>' for label, href in links)
        sections.append(f'<details><summary>{escape(capture)}</summary><ul>{items}</ul></details>')
    body = "".join(sections) or "<p>No capture-specific HTML reports were found.</p>"
    html = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{escape(title)}</title><style>:root{{color-scheme:light dark;--bg:#f4f7fb;--panel:#fff;--text:#172033;--border:#d8e1ec;--link:#0b5cab}}@media(prefers-color-scheme:dark){{:root{{--bg:#111722;--panel:#1a2230;--text:#eef3fa;--border:#344154;--link:#79b8ff}}}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 "Segoe UI",Arial,sans-serif}}main{{max-width:1000px;margin:auto;padding:28px 18px 64px}}a{{color:var(--link)}}.back{{display:inline-block;margin-bottom:14px;font-weight:600;text-decoration:none}}details{{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 16px;margin:12px 0}}summary{{cursor:pointer;font-weight:700}}li{{margin:7px 0;overflow-wrap:anywhere}}</style></head><body><main><a class="back" href="../../test_session_summary.html">&larr; Back to Test Session Summary</a><h1>{escape(title)}</h1><p>Select a PCAP capture to view its detailed reports.</p>{body}</main></body></html>'''
    output = protocol_dir / "index.html"
    output.write_text(html, encoding="utf-8")
    return output


def main() -> int:
    outputs = []
    for relative, title in (("pcap/din70121", "DIN 70121 Detailed Reports"), ("pcap/iso15118", "ISO 15118 / TLS Detailed Reports")):
        directory = REPORTS / relative
        if directory.exists():
            outputs.append(build(directory, title))
    for output in outputs:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
