import argparse
import webbrowser
from pathlib import Path

from services.detail_html_report_service import DetailHtmlReportService
from services.session_html_report_service import TestSessionHtmlReportService as SessionHtmlReportService
from services.session_report_manifest import TestSessionReportManifest


REPORTS_ROOT = Path("reports")
SUMMARY_TXT = REPORTS_ROOT / "test_session_summary.txt"


def section_map(text: str) -> dict[str, list[str]]:
    sections = {}
    current = None
    lines = text.splitlines()
    for index, line in enumerate(lines):
        value = line.strip()
        if not value or set(value) in ({"="}, {"-"}):
            continue
        next_line = lines[index + 1].strip() if index + 1 < len(lines) else ""
        if next_line and set(next_line) == {"-"}:
            current = value
            sections[current] = []
            continue
        if current:
            sections[current].append(value)
    return sections


def values(lines: list[str]) -> dict[str, str]:
    result = {}
    for line in lines:
        if ": " in line:
            key, value = line.split(": ", 1)
            result[key] = value
    return result


def session_from_txt(path: Path) -> dict:
    sections = section_map(path.read_text(encoding="utf-8"))
    session = {}

    identity = values(sections.get("Vehicle Identity", []))
    if identity.get("VIN"):
        session["vehicle_identity"] = {
            "vin": identity["VIN"],
            "status": identity.get("VIN Status", "CONFIRMED"),
            "source": identity.get("VIN Evidence Source", "BLF / VIN_01"),
        }

    blf = values(sections.get("BLF", []))
    if blf:
        session["blf"] = {
            "source_file": _coverage_source(sections, "BLF"),
            "charging_progression": blf.get("Charging progression", "INDETERMINATE"),
            "connector_recognition": blf.get("Connector recognition", "INDETERMINATE"),
            "control_pilot_recognition": blf.get("Control-pilot recognition", "INDETERMINATE"),
            "root_cause_status": blf.get("Root cause status", "UNCONFIRMED"),
            "fault_findings": [line for line in sections.get("BLF", []) if ": " not in line],
        }

    dlt_lines = sections.get("DLT", [])
    if dlt_lines:
        dlt = values(dlt_lines)
        session["dlt"] = {
            "source_file": _coverage_source(sections, "DLT"),
            "fault_findings": [
                f"CRITICAL findings: {dlt.get('CRITICAL findings', '0')}",
                f"ERROR findings: {dlt.get('ERROR findings', '0')}",
                f"WARNING findings: {dlt.get('WARNING findings', '0')}",
            ],
        }
        if dlt.get("Severity counts"):
            session["dlt"]["fault_findings"].append("Severity counts: " + dlt["Severity counts"])

    pcap_lines = sections.get("PCAP", []) or sections.get("PCAP / V2G", [])
    if pcap_lines:
        pcap = values(pcap_lines)
        pcap_sources = [
            value.strip()
            for value in _coverage_source(sections, "PCAP").split(",")
            if value.strip() and value.strip() != "multiple PCAP captures"
        ]
        if not pcap_sources:
            pcap_sources = sorted(
                path.name
                for path in Path("data/pcap").iterdir()
                if path.is_file() and path.suffix.lower() in {".pcap", ".pcapng"}
            ) if Path("data/pcap").exists() else []
        session["pcap"] = {
            "source_file": _coverage_source(sections, "PCAP"),
            "source_files": pcap_sources,
            "network_assessment": {
                "status": pcap.get("Network communication", "INDETERMINATE"),
                "dominant_protocol": pcap.get("Dominant observed protocol"),
            },
        }
        if "DIN 70121" in pcap:
            session["pcap"]["din70121_assessment"] = {
                "status": pcap["DIN 70121"],
                "selected_protocol": pcap.get("DIN 70121 negotiated protocol"),
                "furthest_message": pcap.get("DIN 70121 progression"),
                "session_completion": pcap.get("DIN 70121 session completion"),
            }
        if "ISO 15118 / TLS" in pcap:
            tls = {
                "status": pcap["ISO 15118 / TLS"],
                "tls_version": pcap.get("TLS version"),
            }
            if "TLS server certificate" in pcap:
                tls["server_certificate_observed"] = pcap["TLS server certificate"] == "OBSERVED"
            if "TLS client-certificate authentication" in pcap:
                tls["client_certificate_observed"] = pcap["TLS client-certificate authentication"] == "OBSERVED"
            session["pcap"]["iso15118_tls_assessment"] = tls

    mf4 = values(sections.get("MF4", []))
    if mf4:
        session["mf4"] = {
            "source_file": _coverage_source(sections, "MF4"),
            "charging_progression": mf4.get("Charging progression", "INDETERMINATE"),
            "connector_recognition": mf4.get("Connector recognition", "INDETERMINATE"),
            "control_pilot_recognition": mf4.get("Control-pilot recognition", "INDETERMINATE"),
            "root_cause_status": mf4.get("Root cause status", "UNCONFIRMED"),
            "cp_fault_observed": mf4.get("Explicit CP fault observed", "NO") == "YES",
        }

    if not any(session.get(key) for key in ("blf", "dlt", "pcap", "mf4")):
        raise ValueError("The existing session TXT contains no supported trace sections.")
    return session


def _coverage_source(sections: dict[str, list[str]], label: str) -> str:
    prefix = f"{label}: ANALYZED | "
    for line in sections.get("Trace Coverage", []):
        if line.startswith(prefix):
            return line[len(prefix):]
    return "source not supplied"


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate session HTML from existing TXT reports without trace reanalysis")
    parser.add_argument("--open", action="store_true", help="Open the regenerated session HTML in the default browser")
    args = parser.parse_args()

    if not SUMMARY_TXT.exists():
        print(f"Session TXT not found: {SUMMARY_TXT}")
        print("Run main.py --no-open once to generate the analysis results first.")
        return 2

    session = session_from_txt(SUMMARY_TXT)
    detail_paths = DetailHtmlReportService().generate_all(REPORTS_ROOT)
    manifest = TestSessionReportManifest().build(REPORTS_ROOT)
    html_path = SessionHtmlReportService().save_report(session, manifest)

    print(f"Detail HTML reports generated: {len(detail_paths)}")
    print(f"Session HTML regenerated: {html_path}")
    print("Trace analysis was not rerun.")

    if args.open:
        webbrowser.open(Path(html_path).resolve().as_uri())
        print("Opened session HTML in the default browser.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
