from collections import Counter, defaultdict
from datetime import timedelta
from statistics import median
from typing import Any

from models.processed_trace import ProcessedTrace


class PcapAnalysisService:
    def analyze(
        self,
        trace: ProcessedTrace,
        bin_seconds: int = 10,
        baseline_bins: int = 6,
        change_factor: float = 2.0,
    ) -> dict[str, Any]:
        if trace.metadata.trace_type != "PCAP":
            raise ValueError("PcapAnalysisService requires a PCAP trace")

        if bin_seconds < 1:
            raise ValueError("bin_seconds must be greater than zero")

        if baseline_bins < 1:
            raise ValueError("baseline_bins must be greater than zero")

        if change_factor <= 1.0:
            raise ValueError("change_factor must be greater than 1.0")

        if trace.is_empty:
            return self._empty_result(
                trace,
                bin_seconds,
                baseline_bins,
                change_factor,
            )

        events = sorted(trace.events, key=lambda event: event.timestamp)
        start_timestamp = events[0].timestamp
        end_timestamp = events[-1].timestamp
        duration_seconds = (end_timestamp - start_timestamp).total_seconds()

        protocols = Counter()
        ether_types = Counter()
        mac_pairs = Counter()
        frame_sizes = Counter()
        payload_sizes = Counter()
        vlan_ids = Counter()
        timeline = defaultdict(
            lambda: {
                "packet_count": 0,
                "captured_bytes": 0,
                "protocols": Counter(),
                "frame_sizes": Counter(),
            }
        )

        for event in events:
            payload = event.payload
            protocol = payload.get("protocol", "UNKNOWN")
            ether_type = payload.get("ether_type")
            src_mac = payload.get("src_mac")
            dst_mac = payload.get("dst_mac")
            captured_length = payload.get("captured_length", 0)
            payload_length = self._payload_length(payload)
            elapsed = (event.timestamp - start_timestamp).total_seconds()
            bin_index = int(elapsed) // bin_seconds

            protocols[protocol] += 1
            frame_sizes[captured_length] += 1
            payload_sizes[payload_length] += 1

            if ether_type is not None:
                ether_types[ether_type] += 1

            if src_mac and dst_mac:
                mac_pairs[(src_mac, dst_mac)] += 1

            for vlan_id in payload.get("vlan_ids", []):
                vlan_ids[vlan_id] += 1

            timeline[bin_index]["packet_count"] += 1
            timeline[bin_index]["captured_bytes"] += captured_length
            timeline[bin_index]["protocols"][protocol] += 1
            timeline[bin_index]["frame_sizes"][captured_length] += 1

        timeline_rows = self._build_timeline(
            timeline,
            start_timestamp,
            bin_seconds,
        )
        transition = self._detect_transition(
            timeline_rows,
            baseline_bins,
            change_factor,
        )

        return {
            "capture": {
                "file_name": trace.metadata.file_name,
                "file_path": str(trace.metadata.file_path),
                "file_size_bytes": trace.metadata.file_size_bytes,
                "packet_count": len(events),
                "start_timestamp": start_timestamp,
                "end_timestamp": end_timestamp,
                "duration_seconds": duration_seconds,
                "captured_bytes": sum(
                    size * count for size, count in frame_sizes.items()
                ),
            },
            "protocol_counts": dict(protocols.most_common()),
            "ether_type_counts": {
                f"0x{value:04x}": count
                for value, count in ether_types.most_common()
            },
            "mac_pairs": [
                {
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "packet_count": count,
                }
                for (src_mac, dst_mac), count in mac_pairs.most_common()
            ],
            "frame_size_counts": dict(frame_sizes.most_common()),
            "payload_size_counts": dict(payload_sizes.most_common()),
            "vlan_counts": dict(vlan_ids.most_common()),
            "timeline": timeline_rows,
            "transition_analysis": transition,
            "analysis_parameters": {
                "bin_seconds": bin_seconds,
                "baseline_bins": baseline_bins,
                "change_factor": change_factor,
            },
        }

    def _build_timeline(
        self,
        timeline: dict[int, dict[str, Any]],
        start_timestamp,
        bin_seconds: int,
    ) -> list[dict[str, Any]]:
        rows = []

        for bin_index in sorted(timeline):
            data = timeline[bin_index]
            bin_start = start_timestamp + timedelta(
                seconds=bin_index * bin_seconds
            )
            bin_end = bin_start + timedelta(seconds=bin_seconds)

            rows.append(
                {
                    "bin_index": bin_index,
                    "start_timestamp": bin_start,
                    "end_timestamp": bin_end,
                    "packet_count": data["packet_count"],
                    "captured_bytes": data["captured_bytes"],
                    "protocol_counts": dict(
                        data["protocols"].most_common()
                    ),
                    "frame_size_counts": dict(
                        data["frame_sizes"].most_common()
                    ),
                }
            )

        return rows

    def _detect_transition(
        self,
        timeline: list[dict[str, Any]],
        baseline_bins: int,
        change_factor: float,
    ) -> dict[str, Any]:
        if not timeline:
            return self._empty_transition()

        baseline_rows = timeline[: min(baseline_bins, len(timeline))]
        baseline_counts = [row["packet_count"] for row in baseline_rows]
        baseline = float(median(baseline_counts))
        threshold = baseline * change_factor

        candidate_rows = timeline[len(baseline_rows):]
        periods = []
        active_rows = []

        for row in candidate_rows:
            if row["packet_count"] >= threshold:
                active_rows.append(row)
            elif active_rows:
                periods.append(self._summarize_period(active_rows))
                active_rows = []

        if active_rows:
            periods.append(self._summarize_period(active_rows))

        if not periods:
            return {
                "detected": False,
                "baseline_bin_count": len(baseline_rows),
                "baseline_packets_per_bin": baseline,
                "threshold_packets_per_bin": threshold,
                "peak_packets_per_bin": max(
                    row["packet_count"] for row in timeline
                ),
                "periods": [],
                "primary_period": None,
            }

        primary_period = max(periods, key=lambda period: period["packet_count"])
        primary_start_index = next(
            index
            for index, row in enumerate(timeline)
            if row["start_timestamp"] == primary_period["start_timestamp"]
        )
        primary_end_index = next(
            index
            for index, row in enumerate(timeline)
            if row["end_timestamp"] == primary_period["end_timestamp"]
        )

        pre_rows = timeline[:primary_start_index]
        post_rows = timeline[primary_end_index + 1:]
        baseline_frame_sizes = self._combine_frame_sizes(baseline_rows)
        primary_frame_sizes = Counter(primary_period["frame_size_counts"])
        post_frame_sizes = self._combine_frame_sizes(post_rows)

        pre_rate = self._median_packet_count(pre_rows)
        transition_rate = self._mean_packet_count(
            timeline[primary_start_index:primary_end_index + 1]
        )
        post_rate = self._median_packet_count(post_rows)

        prominent_sizes = self._prominent_transition_sizes(
            baseline_frame_sizes,
            primary_frame_sizes,
            post_frame_sizes,
        )

        post_change_percent = None
        if baseline > 0 and post_rate is not None:
            post_change_percent = ((post_rate - baseline) / baseline) * 100.0

        primary_period = {
            **primary_period,
            "pre_transition_packets_per_bin": pre_rate,
            "transition_packets_per_bin": transition_rate,
            "post_transition_packets_per_bin": post_rate,
            "post_vs_baseline_change_percent": post_change_percent,
            "prominent_transition_frame_sizes": prominent_sizes,
        }

        return {
            "detected": True,
            "baseline_bin_count": len(baseline_rows),
            "baseline_packets_per_bin": baseline,
            "threshold_packets_per_bin": threshold,
            "peak_packets_per_bin": max(
                row["packet_count"] for row in timeline
            ),
            "periods": periods,
            "primary_period": primary_period,
        }

    def _summarize_period(
        self,
        rows: list[dict[str, Any]],
    ) -> dict[str, Any]:
        frame_sizes = Counter()
        protocols = Counter()

        for row in rows:
            frame_sizes.update(row["frame_size_counts"])
            protocols.update(row["protocol_counts"])

        return {
            "start_timestamp": rows[0]["start_timestamp"],
            "end_timestamp": rows[-1]["end_timestamp"],
            "bin_count": len(rows),
            "packet_count": sum(row["packet_count"] for row in rows),
            "captured_bytes": sum(row["captured_bytes"] for row in rows),
            "peak_packets_per_bin": max(
                row["packet_count"] for row in rows
            ),
            "protocol_counts": dict(protocols.most_common()),
            "frame_size_counts": dict(frame_sizes.most_common()),
        }

    def _combine_frame_sizes(
        self,
        rows: list[dict[str, Any]],
    ) -> Counter:
        counts = Counter()

        for row in rows:
            counts.update(row["frame_size_counts"])

        return counts

    def _prominent_transition_sizes(
        self,
        baseline_sizes: Counter,
        transition_sizes: Counter,
        post_sizes: Counter,
    ) -> list[dict[str, Any]]:
        results = []
        baseline_total = sum(baseline_sizes.values())
        transition_total = sum(transition_sizes.values())
        post_total = sum(post_sizes.values())

        if transition_total == 0:
            return results

        for frame_size, transition_count in transition_sizes.most_common():
            transition_share = transition_count / transition_total
            baseline_share = (
                baseline_sizes[frame_size] / baseline_total
                if baseline_total
                else 0.0
            )
            post_share = (
                post_sizes[frame_size] / post_total
                if post_total
                else 0.0
            )
            reference_share = max(baseline_share, post_share)

            if transition_share >= 0.01 and (
                reference_share == 0.0
                or transition_share >= reference_share * 3.0
            ):
                results.append(
                    {
                        "frame_size": frame_size,
                        "transition_count": transition_count,
                        "transition_share": transition_share,
                        "baseline_share": baseline_share,
                        "post_share": post_share,
                    }
                )

        return results

    def _median_packet_count(
        self,
        rows: list[dict[str, Any]],
    ) -> float | None:
        if not rows:
            return None

        return float(median(row["packet_count"] for row in rows))

    def _mean_packet_count(
        self,
        rows: list[dict[str, Any]],
    ) -> float | None:
        if not rows:
            return None

        return sum(row["packet_count"] for row in rows) / len(rows)

    def _payload_length(self, payload: dict[str, Any]) -> int:
        for key in (
            "ethernet_payload_length",
            "transport_payload_length",
        ):
            value = payload.get(key)

            if isinstance(value, int):
                return value

        return 0

    def _empty_transition(self) -> dict[str, Any]:
        return {
            "detected": False,
            "baseline_bin_count": 0,
            "baseline_packets_per_bin": 0.0,
            "threshold_packets_per_bin": 0.0,
            "peak_packets_per_bin": 0,
            "periods": [],
            "primary_period": None,
        }

    def _empty_result(
        self,
        trace: ProcessedTrace,
        bin_seconds: int,
        baseline_bins: int,
        change_factor: float,
    ) -> dict[str, Any]:
        return {
            "capture": {
                "file_name": trace.metadata.file_name,
                "file_path": str(trace.metadata.file_path),
                "file_size_bytes": trace.metadata.file_size_bytes,
                "packet_count": 0,
                "start_timestamp": None,
                "end_timestamp": None,
                "duration_seconds": 0.0,
                "captured_bytes": 0,
            },
            "protocol_counts": {},
            "ether_type_counts": {},
            "mac_pairs": [],
            "frame_size_counts": {},
            "payload_size_counts": {},
            "vlan_counts": {},
            "timeline": [],
            "transition_analysis": self._empty_transition(),
            "analysis_parameters": {
                "bin_seconds": bin_seconds,
                "baseline_bins": baseline_bins,
                "change_factor": change_factor,
            },
        }
