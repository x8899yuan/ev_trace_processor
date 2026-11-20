from collections import Counter

from readers.asc_reader import AscTrace


class AscStatisticsService:
    def analyze(self, trace: AscTrace, top_n: int = 20) -> dict:
        messages = trace.messages
        if not messages:
            return {
                "message_count": 0,
                "first_timestamp": None,
                "last_timestamp": None,
                "duration_seconds": 0.0,
                "messages_per_second": 0.0,
                "data_bytes": 0,
                "average_payload_bytes": 0.0,
                "top_can_ids": [],
                "channel_counts": {},
                "direction_counts": {},
                "payload_length_counts": {},
            }
        timestamps = [message.timestamp for message in messages]
        first_timestamp = min(timestamps)
        last_timestamp = max(timestamps)
        duration = max(0.0, last_timestamp - first_timestamp)
        data_bytes = sum(message.data_length for message in messages)
        id_counts = Counter(message.arbitration_id for message in messages)
        channel_counts = Counter(message.channel for message in messages)
        direction_counts = Counter(message.direction for message in messages)
        payload_lengths = Counter(message.data_length for message in messages)
        return {
            "message_count": len(messages),
            "first_timestamp": first_timestamp,
            "last_timestamp": last_timestamp,
            "duration_seconds": duration,
            "messages_per_second": len(messages) / duration if duration else 0.0,
            "data_bytes": data_bytes,
            "average_payload_bytes": data_bytes / len(messages),
            "top_can_ids": [
                {"arbitration_id": arbitration_id, "hex_id": f"0x{arbitration_id:X}", "count": count}
                for arbitration_id, count in id_counts.most_common(max(0, top_n))
            ],
            "channel_counts": dict(sorted(channel_counts.items())),
            "direction_counts": dict(sorted(direction_counts.items())),
            "payload_length_counts": dict(sorted(payload_lengths.items())),
        }
