import argparse
import webbrowser
from pathlib import Path

from services.session_processor_service import SessionProcessorService
from services.session_trace_handlers import SessionTraceHandlers


SUPPORTED = {
    "blf": (Path("data/blf"), {".blf"}),
    "dlt": (Path("data/dlt"), {".dlt"}),
    "pcap": (Path("data/pcap"), {".pcap", ".pcapng"}),
    "mf4": (Path("data/MF4"), {".mf4"}),
    "asc": (Path("data/asc"), {".asc"}),
}


def discover_traces() -> dict[str, list[Path]]:
    discovered = {}
    for trace_type, (directory, suffixes) in SUPPORTED.items():
        if not directory.exists():
            discovered[trace_type] = []
            continue
        discovered[trace_type] = sorted(
            {
                path
                for path in directory.iterdir()
                if path.is_file() and path.suffix.lower() in suffixes
            }
        )
    return discovered


def print_discovery(discovered: dict[str, list[Path]]) -> None:
    print("DISCOVERED TRACES")
    print("=" * 80)
    for trace_type in ("blf", "dlt", "pcap", "mf4", "asc"):
        files = discovered[trace_type]
        if not files:
            continue
        print(f"{trace_type.upper()}: {len(files)}")
        for path in files:
            print(f"  {path}")
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="EV trace processor")
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Generate reports without opening the session HTML report.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    print("=" * 80)
    print("EV TRACE PROCESSOR")
    print("=" * 80)
    print()

    discovered = discover_traces()
    if not any(discovered.values()):
        print("No supported traces were provided.")
        print("Place at least one BLF, DLT, PCAP, MF4, or ASC trace in its data directory.")
        return 2

    print_discovery(discovered)
    print("Session-association assumption:")
    print("Input traces are treated as belonging to the same vehicle and testing session.")
    print("The user is responsible for supplying a coherent trace set.")
    print()

    try:
        processor = SessionProcessorService(
            handlers=SessionTraceHandlers().build(),
        )
        result = processor.process(discovered)
    except Exception as exc:
        print("PROCESSING FAILED")
        print("=" * 80)
        print(f"{type(exc).__name__}: {exc}")
        return 1

    print("PROCESSING COMPLETE")
    print("=" * 80)
    print("Processed trace types: " + ", ".join(value.upper() for value in result["processed_trace_types"]))
    identity = result.get("vehicle_identity")
    if identity and identity.get("vin"):
        print(f"VIN: {identity['vin']}")
        print(f"VIN evidence: {identity.get('source', 'BLF')}")
    print(f"Session TXT:  {result['summary_path']}")
    print(f"Session HTML: {result['html_path']}")

    html_path = Path(result["html_path"]).resolve()
    if not args.no_open:
        webbrowser.open(html_path.as_uri())
        print("Opened session HTML in the default browser.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
