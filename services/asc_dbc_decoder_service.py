from collections import Counter
from pathlib import Path

from readers.asc_reader import AscTrace


class AscDbcDecoderService:
    def __init__(self, database=None):
        self.database = database

    def decode(
        self,
        trace: AscTrace,
        dbc_file: Path | None = None,
        target_signals=None,
    ) -> dict:
        database = self.database or self._load_database(dbc_file)
        requested_signals = self._target_signal_set(target_signals)
        relevant_messages = self._relevant_messages(database, requested_signals)
        samples = []
        decoded_signal_names = set()
        message_name_counts = Counter()
        unmatched_ids = Counter()
        decode_failure_ids = Counter()
        matched_message_count = 0
        decoded_message_count = 0
        filtered_message_count = 0

        for message in trace.messages:
            if relevant_messages is not None:
                dbc_message = relevant_messages.get(message.arbitration_id)
                if dbc_message is None:
                    filtered_message_count += 1
                    continue
            else:
                dbc_message = self._message_by_frame_id(database, message.arbitration_id)
                if dbc_message is None:
                    unmatched_ids[message.arbitration_id] += 1
                    continue
            matched_message_count += 1
            try:
                decoded = dbc_message.decode(message.data, decode_choices=True)
            except Exception:
                decode_failure_ids[message.arbitration_id] += 1
                continue
            decoded_message_count += 1
            message_name = str(getattr(dbc_message, "name", f"0x{message.arbitration_id:X}"))
            message_name_counts[message_name] += 1
            for signal_name, value in decoded.items():
                signal_name = str(signal_name)
                if requested_signals is not None and signal_name not in requested_signals:
                    continue
                decoded_signal_names.add(signal_name)
                samples.append(
                    {
                        "timestamp": message.timestamp,
                        "channel": message.channel,
                        "arbitration_id": message.arbitration_id,
                        "hex_id": f"0x{message.arbitration_id:X}",
                        "is_extended_id": message.is_extended_id,
                        "direction": message.direction,
                        "is_fd": message.is_fd,
                        "message_name": message_name,
                        "signal_name": signal_name,
                        "value": self._serializable_value(value),
                    }
                )

        return {
            "source_file": str(trace.source_file),
            "message_count": len(trace.messages),
            "matched_message_count": matched_message_count,
            "unmatched_message_count": sum(unmatched_ids.values()),
            "filtered_message_count": filtered_message_count,
            "decoded_message_count": decoded_message_count,
            "decode_failure_count": sum(decode_failure_ids.values()),
            "decoded_signal_count": len(samples),
            "unique_decoded_message_count": len(message_name_counts),
            "unique_decoded_signal_count": len(decoded_signal_names),
            "target_signal_filter_applied": requested_signals is not None,
            "requested_signals": sorted(requested_signals) if requested_signals is not None else [],
            "message_name_counts": dict(message_name_counts.most_common()),
            "unmatched_can_ids": self._counter_rows(unmatched_ids),
            "decode_failure_can_ids": self._counter_rows(decode_failure_ids),
            "signal_samples": samples,
        }

    def _target_signal_set(self, target_signals):
        if target_signals is None:
            return None
        return frozenset(str(signal) for signal in target_signals)

    def _relevant_messages(self, database, requested_signals):
        if requested_signals is None:
            return None
        relevant = {}
        for message in getattr(database, "messages", ()):
            signal_names = {
                str(getattr(signal, "name", ""))
                for signal in getattr(message, "signals", ())
            }
            if signal_names & requested_signals:
                relevant[int(message.frame_id)] = message
        return relevant

    def _load_database(self, dbc_file: Path | None):
        if dbc_file is None:
            raise ValueError("A DBC file is required when no database object is supplied")
        path = Path(dbc_file)
        if not path.exists():
            raise FileNotFoundError(f"DBC file not found: {path}")
        try:
            import cantools
        except ImportError as error:
            raise RuntimeError("cantools is required for ASC DBC decoding") from error
        return cantools.database.load_file(str(path))

    def _message_by_frame_id(self, database, arbitration_id: int):
        try:
            return database.get_message_by_frame_id(arbitration_id)
        except (KeyError, LookupError):
            return None

    def _serializable_value(self, value):
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(value)

    def _counter_rows(self, counter: Counter) -> list[dict]:
        return [
            {
                "arbitration_id": arbitration_id,
                "hex_id": f"0x{arbitration_id:X}",
                "count": count,
            }
            for arbitration_id, count in counter.most_common()
        ]
