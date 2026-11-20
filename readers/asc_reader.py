from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import re


@dataclass(frozen=True)
class AscMessage:
    timestamp: float
    channel: int
    arbitration_id: int
    is_extended_id: bool
    direction: str
    dlc: int
    data_length: int
    data: bytes
    is_fd: bool
    brs: bool | None = None
    esi: bool | None = None


@dataclass
class AscTrace:
    source_file: Path
    start_time: datetime | None = None
    timestamp_mode: str | None = None
    numeric_base: str | None = None
    messages: list[AscMessage] = field(default_factory=list)
    record_counts: dict[str, int] = field(default_factory=dict)
    ignored_line_count: int = 0
    malformed_line_count: int = 0


class AscReader:
    DATE_FORMAT = "%a %b %d %H:%M:%S %Y"
    HEX_CHARS = frozenset("0123456789abcdefABCDEF")
    CLASSIC_PATTERN = re.compile(
        r"^\s*(?P<timestamp>\d+(?:\.\d+)?)\s+"
        r"(?P<channel>\d+)\s+"
        r"(?P<identifier>[0-9A-Fa-f]+x?)\s+"
        r"(?P<direction>Rx|Tx)\s+"
        r"(?P<frame_type>[DdRr])\s+"
        r"(?P<dlc>[0-9A-Fa-f]+)"
        r"(?P<rest>.*)$"
    )
    CANFD_PATTERN = re.compile(
        r"^\s*(?P<timestamp>\d+(?:\.\d+)?)\s+CANFD\s+"
        r"(?P<channel>\d+)\s+"
        r"(?P<direction>Rx|Tx)\s+"
        r"(?P<identifier>[0-9A-Fa-f]+x?)\s+"
        r"(?P<brs>[01])\s+(?P<esi>[01])\s+"
        r"(?P<dlc>[0-9A-Fa-f]+)\s+"
        r"(?P<data_length>\d+)"
        r"(?P<rest>.*)$"
    )

    def read(self, path: Path) -> AscTrace:
        source = Path(path)
        if not source.exists():
            raise FileNotFoundError(f"ASC file not found: {source}")
        trace = AscTrace(source_file=source)
        with source.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                self._consume_line(line.rstrip("\r\n"), trace)
        return trace

    def parse_line(self, line: str) -> AscMessage | None:
        match = self.CANFD_PATTERN.match(line)
        if match:
            return self._parse_canfd(match)
        match = self.CLASSIC_PATTERN.match(line)
        if match:
            return self._parse_classic(match)
        return None

    def _consume_line(self, line: str, trace: AscTrace) -> None:
        stripped = line.strip()
        if not stripped:
            return
        if stripped.startswith("date "):
            trace.start_time = self._parse_date(stripped[5:])
            return
        if stripped.startswith("base "):
            parts = stripped.split()
            trace.numeric_base = parts[1] if len(parts) > 1 else None
            trace.timestamp_mode = parts[3] if len(parts) > 3 and parts[2] == "timestamps" else None
            return
        if stripped in {"Begin Triggerblock", "End Triggerblock"}:
            return
        message = self.parse_line(line)
        if message:
            trace.messages.append(message)
            key = "can_fd" if message.is_fd else "can"
            trace.record_counts[key] = trace.record_counts.get(key, 0) + 1
            return
        record_type = self._record_type(stripped)
        if record_type:
            trace.record_counts[record_type] = trace.record_counts.get(record_type, 0) + 1
            trace.ignored_line_count += 1
        elif stripped[0].isdigit():
            trace.malformed_line_count += 1
        else:
            trace.ignored_line_count += 1

    def _parse_canfd(self, match: re.Match) -> AscMessage:
        values = match.groupdict()
        data_length = int(values["data_length"])
        tokens = values["rest"].split()
        data = self._data_bytes(tokens, data_length)
        return AscMessage(
            timestamp=float(values["timestamp"]),
            channel=int(values["channel"]),
            arbitration_id=self._identifier(values["identifier"]),
            is_extended_id=values["identifier"].lower().endswith("x"),
            direction=values["direction"],
            dlc=int(values["dlc"], 16),
            data_length=data_length,
            data=data,
            is_fd=True,
            brs=values["brs"] == "1",
            esi=values["esi"] == "1",
        )

    def _parse_classic(self, match: re.Match) -> AscMessage:
        values = match.groupdict()
        dlc = int(values["dlc"], 16)
        data = b"" if values["frame_type"].lower() == "r" else self._data_bytes(values["rest"].split(), dlc)
        return AscMessage(
            timestamp=float(values["timestamp"]),
            channel=int(values["channel"]),
            arbitration_id=self._identifier(values["identifier"]),
            is_extended_id=values["identifier"].lower().endswith("x"),
            direction=values["direction"],
            dlc=dlc,
            data_length=len(data),
            data=data,
            is_fd=False,
        )

    def _data_bytes(self, tokens: list[str], expected: int) -> bytes:
        if len(tokens) < expected:
            raise ValueError(f"Expected {expected} data bytes, found {len(tokens)}")
        values = bytearray(expected)
        for index in range(expected):
            token = tokens[index]
            if len(token) != 2 or token[0] not in self.HEX_CHARS or token[1] not in self.HEX_CHARS:
                raise ValueError(f"Expected {expected} data bytes, found {index}")
            values[index] = int(token, 16)
        return bytes(values)

    def _identifier(self, value: str) -> int:
        return int(value[:-1] if value.lower().endswith("x") else value, 16)

    def _parse_date(self, value: str) -> datetime | None:
        try:
            return datetime.strptime(value, self.DATE_FORMAT)
        except ValueError:
            return None

    def _record_type(self, stripped: str) -> str | None:
        parts = stripped.split()
        if len(parts) < 2 or not parts[0][0].isdigit():
            return None
        if parts[1] == "ETH":
            return "ethernet"
        if parts[1] == "Li":
            return "lin"
        return None
