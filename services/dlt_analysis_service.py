import re
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any, Iterable

from models.processed_trace import ProcessedTrace


class DltAnalysisService:
    SEVERITY_BY_TYPE_INFO = {
        1: "FATAL",
        2: "ERROR",
        3: "WARN",
        4: "INFO",
        5: "DEBUG",
        6: "VERBOSE",
    }

    DEFAULT_FINDING_TERMS = (
        "error",
        "failed",
        "failure",
        "fatal",
        "fault",
        "timeout",
        "timed out",
        "unavailable",
        "disconnect",
        "disconnected",
        "reset",
        "shutdown",
        "terminated",
        "exception",
        "denied",
        "invalid",
    )

    def analyze(
        self,
        traces: ProcessedTrace | Iterable[ProcessedTrace],
        bin_seconds: int = 10,
        top_n: int = 25,
        finding_terms: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        trace_list = self._normalize_traces(traces)

        if bin_seconds < 1:
            raise ValueError("bin_seconds must be greater than zero")

        if top_n < 1:
            raise ValueError("top_n must be greater than zero")

        terms = tuple(
            term.lower()
            for term in (
                finding_terms
                if finding_terms is not None
                else self.DEFAULT_FINDING_TERMS
            )
            if term
        )
        patterns = {
            term: re.compile(rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])", re.IGNORECASE)
            for term in terms
        }

        events = sorted(
            (
                (trace.metadata.file_name, event)
                for trace in trace_list
                for event in trace.events
            ),
            key=lambda item: item[1].timestamp,
        )

        if not events:
            return self._empty_result(trace_list, bin_seconds, top_n, terms)

        start_timestamp = events[0][1].timestamp
        end_timestamp = events[-1][1].timestamp
        duration_seconds = (end_timestamp - start_timestamp).total_seconds()

        ecu_counts = Counter()
        application_counts = Counter()
        context_counts = Counter()
        app_context_counts = Counter()
        severity_counts = Counter()
        message_type_counts = Counter()
        message_type_info_counts = Counter()
        verbose_counts = Counter()
        message_id_counts = Counter()
        argument_type_counts = Counter()
        source_file_counts = Counter()
        keyword_counts = Counter()
        finding_category_counts = Counter()
        signature_counts = Counter()
        signature_metadata = {}
        category_examples = defaultdict(list)
        timeline = defaultdict(
            lambda: {
                "event_count": 0,
                "severity_counts": Counter(),
                "ecu_counts": Counter(),
                "finding_counts": Counter(),
            }
        )

        for source_file, event in events:
            payload = event.payload
            source_file_counts[source_file] += 1

            ecu_id = payload.get("ecu_id")
            application_id = payload.get("application_id")
            context_id = payload.get("context_id")
            message_type = payload.get("message_type")
            message_type_info = payload.get("message_type_info")
            verbose = payload.get("verbose")
            message_id = payload.get("message_id")
            severity = self._severity(message_type, message_type_info)
            message_text = self._message_content(payload)

            if ecu_id:
                ecu_counts[ecu_id] += 1

            if application_id:
                application_counts[application_id] += 1

            if context_id:
                context_counts[context_id] += 1

            if application_id or context_id:
                app_context_counts[(application_id or "", context_id or "")] += 1

            if message_type is not None:
                message_type_counts[message_type] += 1

            if message_type_info is not None:
                message_type_info_counts[message_type_info] += 1

            severity_counts[severity] += 1

            if verbose is True:
                verbose_counts["verbose"] += 1
            elif verbose is False:
                verbose_counts["non_verbose"] += 1
            else:
                verbose_counts["unknown"] += 1

            if message_id is not None:
                message_id_counts[message_id] += 1

            for argument in payload.get("arguments", []):
                argument_type = argument.get("type")
                if argument_type:
                    argument_type_counts[argument_type] += 1

            elapsed = (event.timestamp - start_timestamp).total_seconds()
            bin_index = int(elapsed) // bin_seconds
            row = timeline[bin_index]
            row["event_count"] += 1
            row["severity_counts"][severity] += 1

            if ecu_id:
                row["ecu_counts"][ecu_id] += 1

            matched_terms = [
                term for term, pattern in patterns.items()
                if pattern.search(message_text)
            ]
            keyword_counts.update(matched_terms)
            category = self._finding_category(severity, matched_terms)

            if category:
                finding_category_counts[category] += 1
                row["finding_counts"][category] += 1
                signature = self._normalize_signature(message_text)
                signature_key = (
                    category,
                    source_file,
                    ecu_id or "",
                    application_id or "",
                    context_id or "",
                    signature,
                )
                signature_counts[signature_key] += 1

                if signature_key not in signature_metadata:
                    signature_metadata[signature_key] = {
                        "category": category,
                        "severity": severity,
                        "source_file": source_file,
                        "ecu_id": ecu_id,
                        "application_id": application_id,
                        "context_id": context_id,
                        "event_name": event.event_name,
                        "signature": signature,
                        "first_timestamp": event.timestamp,
                        "last_timestamp": event.timestamp,
                        "matched_terms": matched_terms,
                        "example_message": message_text,
                    }
                else:
                    signature_metadata[signature_key]["last_timestamp"] = event.timestamp
                    existing = set(signature_metadata[signature_key]["matched_terms"])
                    signature_metadata[signature_key]["matched_terms"] = sorted(
                        existing.union(matched_terms)
                    )

                if len(category_examples[category]) < top_n:
                    category_examples[category].append(
                        {
                            "timestamp": event.timestamp,
                            "source_file": source_file,
                            "ecu_id": ecu_id,
                            "application_id": application_id,
                            "context_id": context_id,
                            "severity": severity,
                            "event_name": event.event_name,
                            "matched_terms": matched_terms,
                            "message": message_text,
                        }
                    )

        finding_signatures = []
        for signature_key, count in signature_counts.most_common():
            item = dict(signature_metadata[signature_key])
            item["occurrence_count"] = count
            finding_signatures.append(item)

        return {
            "capture": {
                "trace_count": len(trace_list),
                "source_files": [trace.metadata.file_name for trace in trace_list],
                "event_count": len(events),
                "start_timestamp": start_timestamp,
                "end_timestamp": end_timestamp,
                "duration_seconds": duration_seconds,
            },
            "source_file_counts": dict(source_file_counts.most_common()),
            "ecu_counts": dict(ecu_counts.most_common()),
            "application_counts": dict(application_counts.most_common(top_n)),
            "context_counts": dict(context_counts.most_common(top_n)),
            "application_context_counts": [
                {
                    "application_id": application_id,
                    "context_id": context_id,
                    "event_count": count,
                }
                for (application_id, context_id), count
                in app_context_counts.most_common(top_n)
            ],
            "severity_counts": dict(severity_counts.most_common()),
            "message_type_counts": dict(message_type_counts.most_common()),
            "message_type_info_counts": dict(message_type_info_counts.most_common()),
            "verbosity_counts": dict(verbose_counts),
            "message_id_counts": dict(message_id_counts.most_common(top_n)),
            "argument_type_counts": dict(argument_type_counts.most_common()),
            "keyword_counts": dict(keyword_counts.most_common()),
            "finding_category_counts": dict(finding_category_counts.most_common()),
            "critical_findings": category_examples["critical"],
            "error_findings": category_examples["error"],
            "warning_findings": category_examples["warning"],
            "keyword_observations": category_examples["keyword_observation"],
            "finding_signatures": finding_signatures[:top_n],
            "unique_finding_signature_count": len(finding_signatures),
            "timeline": self._build_timeline(timeline, start_timestamp, bin_seconds),
            "analysis_parameters": {
                "bin_seconds": bin_seconds,
                "top_n": top_n,
                "finding_terms": list(terms),
            },
        }

    def _normalize_traces(
        self,
        traces: ProcessedTrace | Iterable[ProcessedTrace],
    ) -> list[ProcessedTrace]:
        if isinstance(traces, ProcessedTrace):
            trace_list = [traces]
        else:
            trace_list = list(traces)

        if not trace_list:
            raise ValueError("At least one DLT trace is required")

        for trace in trace_list:
            if trace.metadata.trace_type != "DLT":
                raise ValueError("DltAnalysisService requires DLT traces")

        return trace_list

    def _severity(self, message_type: Any, message_type_info: Any) -> str:
        if message_type == 0:
            return self.SEVERITY_BY_TYPE_INFO.get(message_type_info, "LOG_OTHER")
        if message_type == 1:
            return "APP_TRACE"
        if message_type == 2:
            return "NW_TRACE"
        if message_type == 3:
            return "CONTROL"
        return "UNKNOWN"

    def _finding_category(
        self,
        severity: str,
        matched_terms: list[str],
    ) -> str | None:
        if severity == "FATAL":
            return "critical"
        if severity == "ERROR":
            return "error"
        if severity == "WARN":
            return "warning"
        if matched_terms:
            return "keyword_observation"
        return None

    def _message_content(self, payload: dict[str, Any]) -> str:
        arguments = payload.get("arguments", [])

        if arguments:
            return " ".join(
                str(argument.get("value", ""))
                for argument in arguments
            ).strip()

        message = str(payload.get("message", ""))
        argument_count = payload.get("number_of_arguments")

        if isinstance(argument_count, int) and argument_count > 0:
            pattern = re.compile(rf"\bverbose\s+{argument_count}\s+", re.IGNORECASE)
            match = pattern.search(message)
            if match:
                return message[match.end():].strip()

        return message.strip()

    def _normalize_signature(self, message: str) -> str:
        normalized = message.lower()
        normalized = re.sub(r"https?://\S+", "<url>", normalized)
        normalized = re.sub(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", "<mac>", normalized)
        normalized = re.sub(r"\b0x[0-9a-f]+\b", "<hex>", normalized)
        normalized = re.sub(r"\b\d+(?:\.\d+)?\b", "<num>", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized

    def _build_timeline(
        self,
        timeline: dict[int, dict[str, Any]],
        start_timestamp,
        bin_seconds: int,
    ) -> list[dict[str, Any]]:
        rows = []

        for bin_index in sorted(timeline):
            data = timeline[bin_index]
            bin_start = start_timestamp + timedelta(seconds=bin_index * bin_seconds)
            rows.append(
                {
                    "bin_index": bin_index,
                    "start_timestamp": bin_start,
                    "end_timestamp": bin_start + timedelta(seconds=bin_seconds),
                    "event_count": data["event_count"],
                    "severity_counts": dict(data["severity_counts"].most_common()),
                    "ecu_counts": dict(data["ecu_counts"].most_common()),
                    "finding_counts": dict(data["finding_counts"].most_common()),
                }
            )

        return rows

    def _empty_result(
        self,
        traces: list[ProcessedTrace],
        bin_seconds: int,
        top_n: int,
        terms: tuple[str, ...],
    ) -> dict[str, Any]:
        return {
            "capture": {
                "trace_count": len(traces),
                "source_files": [trace.metadata.file_name for trace in traces],
                "event_count": 0,
                "start_timestamp": None,
                "end_timestamp": None,
                "duration_seconds": 0.0,
            },
            "source_file_counts": {},
            "ecu_counts": {},
            "application_counts": {},
            "context_counts": {},
            "application_context_counts": [],
            "severity_counts": {},
            "message_type_counts": {},
            "message_type_info_counts": {},
            "verbosity_counts": {},
            "message_id_counts": {},
            "argument_type_counts": {},
            "keyword_counts": {},
            "finding_category_counts": {},
            "critical_findings": [],
            "error_findings": [],
            "warning_findings": [],
            "keyword_observations": [],
            "finding_signatures": [],
            "unique_finding_signature_count": 0,
            "timeline": [],
            "analysis_parameters": {
                "bin_seconds": bin_seconds,
                "top_n": top_n,
                "finding_terms": list(terms),
            },
        }
