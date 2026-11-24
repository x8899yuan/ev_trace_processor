from html import escape
from pathlib import Path

from services.engineering_value_formatter import EngineeringValueFormatter


class AscChargingHtmlReportService:
    SIGNAL_ORDER = (
        "HVLM_Steckerstatus_A",
        "HVLM_Steckerstatus_B",
        "HVLM_CP_State_A",
        "HVLM_CP_State_B",
        "HVLM_CP_MaxStrom_A",
        "HVLM_CP_MaxStrom_B",
        "HVLM_Ladevorgang_Anf",
        "HVLM_ZustandLadeablauf",
        "KL_Fehler_HV_Heizer",
    )

    def generate(self, analysis: dict, output_path: Path) -> Path:
        output = Path(output_path).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self._document(analysis), encoding="utf-8")
        return output

    def _document(self, analysis: dict) -> str:
        source = Path(str(analysis.get("source_file", "source not supplied"))).name
        return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ASC Charging Inspection Report</title>
<style>{self._styles()}</style>
</head>
<body>
<main>
<h1>ASC CHARGING INSPECTION REPORT</h1>
<p class="source">ASC file: {escape(source)}</p>
{self._assessment_section(analysis)}
{self._conclusion_section(analysis)}
{self._event_timeline_section(analysis)}
{self._signal_timelines_section(analysis)}
{self._heater_fault_section(analysis)}
{self._limitations_section(analysis)}
</main>
</body>
</html>'''

    def _assessment_section(self, analysis: dict) -> str:
        rows = []
        for key, label in (
            ("classification", "Classification"),
            ("charging_progression", "Charging progression"),
            ("connector_recognition", "Connector recognition"),
            ("control_pilot_recognition", "Control-pilot recognition"),
            ("charging_request", "Charging request"),
            ("charging_workflow", "Charging workflow"),
            ("root_cause_status", "Root cause status"),
            ("target_signal_count", "Target signals observed"),
            ("target_sample_count", "Target signal samples"),
        ):
            rows.append(f"<dt>{escape(label)}</dt><dd>{escape(str(analysis.get(key, 'INDETERMINATE')))}</dd>")
        return f'<section><h2>CHARGING ASSESSMENT</h2><dl>{"".join(rows)}</dl></section>'

    def _conclusion_section(self, analysis: dict) -> str:
        value = self._format(analysis.get("engineering_conclusion", "No evidence-supported conclusion available."))
        return f'<section><h2>ENGINEERING CONCLUSION</h2><p>{escape(value)}</p></section>'

    def _event_timeline_section(self, analysis: dict) -> str:
        rows = []
        for event in analysis.get("event_timeline") or []:
            transition_raw = str(event.get("signal_transition", "Unknown"))
            meaning_raw = str(event.get("engineering_meaning", "No engineering interpretation available."))
            row_class = ' class="error-row"' if "fehler" in transition_raw.lower() or "error" in meaning_raw.lower() else ""
            rows.append(
                f"<tr{row_class}>"
                f"<td>{escape(self._time(event.get('timestamp')))}</td>"
                f"<td>{escape(str(event.get('relative_time', 'Unknown')))}</td>"
                f"<td><code>{escape(self._format(transition_raw))}</code></td>"
                f"<td>{escape(self._format(meaning_raw))}</td>"
                "</tr>"
            )
        if not rows:
            rows.append('<tr><td colspan="4">No charging events were derived.</td></tr>')
        reference = self._time(analysis.get("reference_timestamp"))
        return f'''<section>
<h2>CHARGING EVENT TIMELINE</h2>
<p class="reference">Reference timestamp: {escape(reference)} (+0.000 s)</p>
<div class="table-wrap"><table class="timeline-table">
<colgroup><col class="time"><col class="relative"><col class="transition"><col class="meaning"></colgroup>
<thead><tr><th>ASC timestamp</th><th>Relative time</th><th>Signal transition</th><th>Engineering meaning</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table></div>
</section>'''

    def _signal_timelines_section(self, analysis: dict) -> str:
        signals = analysis.get("signals") or {}
        cards = []
        for name in self.SIGNAL_ORDER:
            signal = signals.get(name)
            if not signal:
                continue
            summary_rows = []
            for label, value in (
                ("Samples", signal.get("sample_count", 0)),
                ("First timestamp", self._time(signal.get("first_timestamp"))),
                ("Last timestamp", self._time(signal.get("last_timestamp"))),
                ("First value", self._translated_value(signal.get("first_value"), signal.get("first_value_translation"))),
                ("Last value", self._translated_value(signal.get("last_value"), signal.get("last_value_translation"))),
                ("Unique values", self._translated_values(signal)),
                ("State transitions", signal.get("transition_count", 0)),
            ):
                summary_rows.append(f"<dt>{escape(str(label))}</dt><dd>{escape(str(value))}</dd>")
            transition_rows = []
            for transition in (signal.get("transitions") or [])[:20]:
                transition_rows.append(
                    "<tr>"
                    f"<td>{escape(self._time(transition.get('timestamp')))}</td>"
                    f"<td>{escape(self._translated_value(transition.get('value'), transition.get('value_translation')))}</td>"
                    f"<td>{escape(str(transition.get('channel', 'Unknown')))}</td>"
                    f"<td>{escape(self._can_id(transition.get('arbitration_id')))}</td>"
                    f"<td>{escape(str(transition.get('message_name', 'Unknown')))}</td>"
                    "</tr>"
                )
            omitted = len(signal.get("transitions") or []) - len(transition_rows)
            omitted_note = f'<p class="muted">{omitted} additional transitions omitted.</p>' if omitted > 0 else ""
            cards.append(f'''<article class="signal-card">
<h3>{escape(name)}</h3>
<dl>{"".join(summary_rows)}</dl>
<div class="table-wrap compact"><table class="transition-table">
<thead><tr><th>Timestamp</th><th>Value</th><th>Channel</th><th>CAN ID</th><th>Message</th></tr></thead>
<tbody>{"".join(transition_rows) or '<tr><td colspan="5">No transitions observed.</td></tr>'}</tbody>
</table></div>{omitted_note}
</article>''')
        content = "".join(cards) or '<p>No targeted charging signals were observed.</p>'
        return f'<section><h2>SIGNAL TIMELINES</h2><div class="signal-list">{content}</div></section>'

    def _heater_fault_section(self, analysis: dict) -> str:
        heater = analysis.get("heater_fault_analysis") or {}
        rows = []
        for label, value in (
            ("Heater samples", heater.get("sample_count", 0)),
            ("Fault observed", "YES" if heater.get("fault_observed") else "NO"),
            ("Fault intervals", heater.get("fault_interval_count", 0)),
            ("Fault active at trace end", "YES" if heater.get("active_at_trace_end") else "NO"),
            ("Charging causal status", heater.get("charging_causal_status", "UNCONFIRMED")),
        ):
            rows.append(f"<dt>{escape(str(label))}</dt><dd>{escape(str(value))}</dd>")
        intervals = []
        for index, interval in enumerate(heater.get("intervals") or [], start=1):
            end = self._time(interval.get("end_timestamp")) if interval.get("end_timestamp") is not None else "trace end"
            intervals.append(f"<li>Interval {index}: {escape(self._time(interval.get('start_timestamp')))} → {escape(end)}</li>")
        interval_html = f'<ul>{"".join(intervals)}</ul>' if intervals else '<p class="muted">No HV-heater fault intervals were observed.</p>'
        return f'<section><h2>HV HEATER FAULT CORRELATION</h2><dl>{"".join(rows)}</dl>{interval_html}</section>'

    def _limitations_section(self, analysis: dict) -> str:
        values = analysis.get("evidence_limitations") or ["No evidence limitations supplied."]
        items = "".join(f"<li>{escape(self._format(value))}</li>" for value in values)
        return f'<section><h2>EVIDENCE LIMITATIONS</h2><ul>{items}</ul></section>'

    def _translated_value(self, value, translation=None) -> str:
        raw = "Unknown" if value is None else str(value)
        translated = raw if translation is None else str(translation)
        text = raw if translated == raw else f"{raw} ({translated})"
        return self._format(text)

    def _translated_values(self, signal: dict) -> str:
        values = signal.get("unique_values") or []
        translations = signal.get("translated_values") or {}
        rendered = [self._translated_value(value, translations.get(value)) for value in values[:20]]
        if len(values) > 20:
            rendered.append(f"... (+{len(values) - 20})")
        return ", ".join(rendered) if rendered else "None"

    def _format(self, value) -> str:
        return EngineeringValueFormatter().format_text(str(value))

    def _time(self, value) -> str:
        try:
            return f"{float(value):.6f}"
        except (TypeError, ValueError):
            return "Unknown"

    def _can_id(self, value) -> str:
        try:
            return f"0x{int(value):X}"
        except (TypeError, ValueError):
            return "Unknown"

    def _styles(self) -> str:
        return '''
:root { color-scheme:light dark; --bg:#f4f7fb; --panel:#fff; --text:#172033; --muted:#64748b; --border:#d8e1ec; --head:#eef3f8; --error:#fff0ef; --sub:#f8fafc; }
@media(prefers-color-scheme:dark) { :root { --bg:#111722; --panel:#1a2230; --text:#eef3fa; --muted:#aab6c6; --border:#344154; --head:#151d29; --error:#3b2227; --sub:#141c28; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 "Segoe UI",Arial,sans-serif; }
main { max-width:1440px; margin:auto; padding:28px 18px 64px; }
h1 { margin:0 0 4px; }
h2 { margin:0 0 14px; }
h3 { margin:0 0 12px; font-size:17px; }
.source,.reference,.muted { color:var(--muted); }
section { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:20px; margin:16px 0; }
dl { display:grid; grid-template-columns:minmax(210px,30%) 1fr; margin:0; border-top:1px solid var(--border); }
dt,dd { padding:9px 10px; border-bottom:1px solid var(--border); overflow-wrap:anywhere; }
dt { font-weight:700; color:var(--muted); background:var(--head); }
dd { margin:0; }
.table-wrap { overflow-x:auto; border:1px solid var(--border); border-radius:10px; }
table { width:100%; border-collapse:collapse; table-layout:fixed; }
.timeline-table { min-width:1050px; }
.timeline-table col.time { width:150px; }
.timeline-table col.relative { width:125px; }
.timeline-table col.transition { width:44%; }
.timeline-table col.meaning { width:auto; }
th,td { padding:11px 12px; border-bottom:1px solid var(--border); text-align:left; vertical-align:top; }
th { background:var(--head); color:var(--muted); white-space:nowrap; }
td:nth-child(1),.timeline-table td:nth-child(2) { white-space:nowrap; font-variant-numeric:tabular-nums; }
code { white-space:normal; overflow-wrap:anywhere; font-family:Consolas,"Courier New",monospace; color:inherit; }
tr:last-child td { border-bottom:0; }
tr.error-row td { background:var(--error); font-weight:700; }
.signal-list { display:grid; gap:16px; }
.signal-card { border:1px solid var(--border); border-radius:10px; padding:16px; background:var(--sub); }
.signal-card dl { grid-template-columns:minmax(180px,24%) 1fr; }
.compact { margin-top:14px; }
.transition-table { min-width:760px; }
.transition-table th:nth-child(1) { width:145px; }
.transition-table th:nth-child(3) { width:80px; }
.transition-table th:nth-child(4) { width:95px; }
.transition-table th:nth-child(5) { width:150px; }
ul { margin-bottom:0; }
@media(max-width:700px) { main { padding:18px 10px 40px; } dl,.signal-card dl { grid-template-columns:1fr; } }
'''
