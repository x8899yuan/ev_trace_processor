import re
from html import escape
from pathlib import Path

from services.engineering_value_formatter import EngineeringValueFormatter
from services.html_report_renderer import HtmlReportRenderer


class DetailHtmlReportService:
    def __init__(self, renderer: HtmlReportRenderer | None = None) -> None:
        self._renderer = renderer if renderer is not None else HtmlReportRenderer()

    def generate_all(self, reports_root: Path = Path("reports"), run_id: str | None = None) -> list[Path]:
        root = Path(reports_root)
        pattern = f"*_{run_id}.txt" if run_id else "*.txt"
        outputs = []
        for txt_path in sorted(root.rglob(pattern)):
            if txt_path.parent == root and txt_path.name.startswith("session_summary"):
                continue
            html_path = txt_path.with_suffix(".html")
            outputs.append(self.generate_one(txt_path, html_path, root, run_id))
        return outputs

    def generate_one(self, txt_path: Path, html_path: Path, reports_root: Path, run_id: str | None = None) -> Path:
        txt_path = Path(txt_path)
        html_path = Path(html_path)
        root = Path(reports_root).resolve()
        text = txt_path.read_text(encoding="utf-8", errors="replace")
        title, blocks = self._parse(text, txt_path)
        back_link = self._back_link(html_path.resolve(), root, run_id)
        html = self._document(title, txt_path.name, blocks, back_link)
        return self._renderer.write_page(html_path, html)

    def _parse(self, text: str, path: Path) -> tuple[str, list[dict]]:
        lines = text.splitlines()
        title = next((line.strip() for line in lines if line.strip()), path.stem.replace("_", " ").title())
        blocks = []
        current = {"title": "Overview", "lines": []}
        index = 1
        while index < len(lines):
            value = lines[index].strip()
            next_value = lines[index + 1].strip() if index + 1 < len(lines) else ""
            if value and next_value and set(next_value) == {"-"} and value != "ASC timestamp | Relative time | Signal transition | Engineering meaning":
                if current["lines"]:
                    blocks.append(current)
                current = {"title": value, "lines": []}
                index += 2
                continue
            if value and set(value) not in ({"="}, {"-"}):
                current["lines"].append(value)
            index += 1
        if current["lines"]:
            blocks.append(current)
        return title, blocks

    def _document(self, title: str, filename: str, blocks: list[dict], back_link: str) -> str:
        sections = "".join(self._section(block) for block in blocks)
        return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{escape(title)}</title><style>:root{{color-scheme:light dark;--bg:#f4f7fb;--panel:#fff;--text:#172033;--muted:#64748b;--border:#d8e1ec;--accent:#0b5cab;--row:#f8fafc;--error:#fff1f0}}@media(prefers-color-scheme:dark){{:root{{--bg:#111722;--panel:#1a2230;--text:#eef3fa;--muted:#aab6c6;--border:#344154;--accent:#79b8ff;--row:#151d29;--error:#352126}}}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 "Segoe UI",Arial,sans-serif}}main{{max-width:1280px;margin:auto;padding:28px 18px 64px}}a{{color:var(--accent)}}.back{{display:inline-block;margin-bottom:14px;text-decoration:none;font-weight:600}}h1{{margin:0;font-size:30px}}.source{{margin:5px 0 24px;color:var(--muted)}}section{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px 20px;margin:14px 0}}h2{{margin:0 0 14px;font-size:19px}}dl{{display:grid;grid-template-columns:minmax(220px,35%) 1fr;gap:0;margin:0;border-top:1px solid var(--border)}}dt,dd{{padding:9px 10px;border-bottom:1px solid var(--border);overflow-wrap:anywhere}}dt{{margin:0;color:var(--muted);font-weight:600;background:var(--row)}}dd{{margin:0}}ul{{margin:4px 0 0;padding-left:24px}}li{{margin:6px 0;overflow-wrap:anywhere}}.note{{white-space:pre-wrap;overflow-wrap:anywhere;margin:8px 0}}.reference{{margin:0 0 10px;color:var(--muted)}}.table-wrap{{overflow-x:auto;border:1px solid var(--border);border-radius:9px}}table{{width:100%;border-collapse:collapse;min-width:980px}}th,td{{padding:10px 12px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}}th{{background:var(--row);color:var(--muted);font-weight:700;white-space:nowrap}}td:nth-child(1),td:nth-child(2){{font-variant-numeric:tabular-nums}}td:nth-child(3){{width:42%;font-family:Consolas,"Courier New",monospace;overflow-wrap:anywhere}}td:nth-child(4){{width:38%}}tr:last-child td{{border-bottom:0}}tr.error td{{background:var(--error);font-weight:700}}@media(max-width:650px){{dl{{grid-template-columns:1fr}}dt{{border-bottom:0}}main{{padding:18px 10px 40px}}table{{min-width:820px}}}}table{{width:100%;table-layout:fixed;min-width:0}}th,td{{overflow-wrap:anywhere;white-space:normal}}</style></head><body><main><a class="back" href="{escape(back_link, quote=True)}">&larr; Back to Test Session Summary</a><h1>{escape(title)}</h1><p class="source">Detailed report: {escape(filename)}</p>{sections}</main></body></html>'''

    def _section(self, block: dict) -> str:
        if block["title"] == "SIGNAL TIMELINES":
            table = self._asc_signal_timelines_table(block["lines"])
            if table:
                return f'<section><h2>{escape(block["title"])}</h2>{table}</section>'
        if block["title"] == "CHARGING EVENT TIMELINE":
            table = self._charging_event_table(block["lines"])
            if table:
                return f'<section><h2>{escape(block["title"])}</h2>{table}</section>'
        rows = []
        notes = []
        for line in block["lines"]:
            if ": " in line:
                rows.append(tuple(line.split(": ", 1)))
            else:
                notes.append(line)
        content = []
        if rows:
            content.append("<dl>")
            content.extend(f"<dt>{escape(key)}</dt><dd>{escape(value)}</dd>" for key, value in rows)
            content.append("</dl>")
        if notes:
            if len(notes) > 1:
                content.append("<ul>")
                content.extend(f"<li>{escape(line)}</li>" for line in notes)
                content.append("</ul>")
            else:
                content.append(f'<p class="note">{escape(notes[0])}</p>')
        if not content:
            content.append('<p class="note">No additional content.</p>')
        return f'<section><h2>{escape(block["title"])}</h2>{"".join(content)}</section>'

    def _asc_clean_translation(self, value: str) -> str:
        text = str(value)
        pattern = re.compile(r"^(.*?)\s+\(([^()]*)\)\s+\(([^()]*)\)$")
        match = pattern.match(text)
        if not match:
            return text
        raw, first, second = match.groups()
        first_words = set(re.findall(r"[a-z]+", first.lower()))
        second_words = set(re.findall(r"[a-z]+", second.lower()))
        if first_words and second_words and (first_words <= second_words or second_words <= first_words or len(first_words & second_words) >= 2):
            return f"{raw} ({second})"
        return text

    def _asc_signal_timelines_table(self, lines: list[str]) -> str | None:
        import re
        names = {
            "HVLM_Steckerstatus_A", "HVLM_Steckerstatus_B",
            "HVLM_CP_State_A", "HVLM_CP_State_B",
            "HVLM_CP_MaxStrom_A", "HVLM_CP_MaxStrom_B",
            "HVLM_Ladevorgang_Anf", "HVLM_ZustandLadeablauf",
            "KL_Fehler_HV_Heizer", "HVLM_OBG_SollModus",
            "HVLE_OBG_IstModus", "HVLM_V2L_STDSollSpannung",
            "HVLM_V2X_SollFrequenz", "HVLX_V2X_IstModus",
        }
        entries = []
        current = None
        for line in lines:
            value = line.strip()
            if value in names or (value.startswith(("HVLM_", "HVLE_", "HVLX_", "KL_")) and ": " not in value and " | " not in value):
                current = {"name": value, "summary": [], "transitions": []}
                entries.append(current)
            elif current is not None and re.match(r"^\d+(?:\.\d+)?\s*\|", value):
                parts = [part.strip() for part in value.split(" | ")]
                if len(parts) >= 2:
                    current["transitions"].append(parts)
            elif current is not None and ": " in value:
                key, val = value.split(": ", 1)
                current["summary"].append((key, val))
        if not entries:
            return None
        parts = []
        for entry in entries:
            parts.append(f'<h3>{escape(entry["name"])}</h3>')
            if entry["summary"]:
                parts.append('<dl>')
                for key, value in entry["summary"]:
                    parts.append(f'<dt>{escape(key)}</dt><dd>{escape(self._asc_clean_translation(value))}</dd>')
                parts.append('</dl>')
            if entry["transitions"]:
                parts.append('<div class="table-wrap"><table><thead><tr>')
                for label in ("ASC timestamp", "Decoded signal value", "Channel", "CAN ID", "Message"):
                    parts.append(f'<th>{escape(label)}</th>')
                parts.append('</tr></thead><tbody>')
                for row in entry["transitions"]:
                    meta = {}
                    for field in row[2:]:
                        if "=" in field:
                            key, value = field.split("=", 1)
                            meta[key.strip()] = value.strip()
                    cells = (row[0], row[1], meta.get("channel", ""), meta.get("can_id", ""), meta.get("message", ""))
                    parts.append('<tr>' + ''.join(f'<td>{escape(self._asc_clean_translation(cell))}</td>' for cell in cells) + '</tr>')
                parts.append('</tbody></table></div>')
            else:
                parts.append('<p class="note">No decoded transitions available.</p>')
        return ''.join(parts)

    def _charging_event_table(self, lines: list[str]) -> str | None:
        reference = next((line for line in lines if line.startswith("Reference timestamp:")), None)
        header_index = next((i for i, line in enumerate(lines) if line == "ASC timestamp | Relative time | Signal transition | Engineering meaning"), None)
        if header_index is None:
            return None
        formatter = EngineeringValueFormatter()
        data_rows = []
        for line in lines[header_index + 1:]:
            if not line or set(line.replace(" ", "")) == {"-"}:
                continue
            values = [value.strip() for value in line.split(" | ", 3)]
            if len(values) != 4:
                continue
            formatted_values = [formatter.format_text(value) for value in values]
            row_class = ' class="error"' if "Fehler" in values[2] or "error" in values[3].lower() else ""
            cells = "".join(f"<td>{escape(value)}</td>" for value in formatted_values)
            data_rows.append(f"<tr{row_class}>{cells}</tr>")
        if not data_rows:
            return None
        parts = []
        if reference:
            parts.append(f'<p class="reference">{escape(reference)}</p>')
        parts.append('<div class="table-wrap"><table><thead><tr>')
        for label in ("ASC timestamp", "Relative time", "Signal transition", "Engineering meaning"):
            parts.append(f"<th>{escape(label)}</th>")
        parts.append("</tr></thead><tbody>")
        parts.extend(data_rows)
        parts.append("</tbody></table></div>")
        return "".join(parts)

    def _back_link(self, html_path: Path, root: Path, run_id: str | None = None) -> str:
        relative = html_path.relative_to(root)
        depth = len(relative.parents) - 1
        name = f"session_summary_{run_id}.html" if run_id else "session_summary.html"
        return (Path(*([".."] * depth)) / name).as_posix()
