from collections import Counter

from readers.asc_reader import AscTrace


class AscInventoryService:
    def analyze(self, trace: AscTrace) -> dict:
        messages = trace.messages
        channels = Counter(message.channel for message in messages)
        identifiers = Counter(message.arbitration_id for message in messages)
        directions = Counter(message.direction for message in messages)
        return {
            "source_file": str(trace.source_file),
            "start_time": trace.start_time.isoformat() if trace.start_time else None,
            "numeric_base": trace.numeric_base,
            "timestamp_mode": trace.timestamp_mode,
            "message_count": len(messages),
            "classic_can_count": sum(not message.is_fd for message in messages),
            "can_fd_count": sum(message.is_fd for message in messages),
            "standard_id_count": sum(not message.is_extended_id for message in messages),
            "extended_id_count": sum(message.is_extended_id for message in messages),
            "unique_can_id_count": len(identifiers),
            "channels": dict(sorted(channels.items())),
            "directions": dict(sorted(directions.items())),
            "other_record_counts": {
                key: value
                for key, value in trace.record_counts.items()
                if key not in {"can", "can_fd"}
            },
            "ignored_line_count": trace.ignored_line_count,
            "malformed_line_count": trace.malformed_line_count,
        }
