from pathlib import Path

import pytest

from services.session_processor_service import TestSessionProcessorService as SessionProcessorService


class AdapterStub:
    def __init__(self, log):
        self.log = log

    def build_session_inputs(self, **kwargs):
        self.log.append(("adapter", kwargs))
        return {
            "vehicle_identity": kwargs.get("vehicle_identity"),
            "blf": kwargs.get("blf"),
            "dlt": kwargs.get("dlt_analysis"),
            "pcap": kwargs.get("pcap_analysis"),
            "mf4": kwargs.get("mf4"),
        }


class SummaryStub:
    def __init__(self, log, output):
        self.log = log
        self.output = output

    def save_summary(self, **session_inputs):
        self.log.append(("summary", session_inputs))
        return self.output


class ManifestStub:
    def __init__(self, log, manifest=None):
        self.log = log
        self.manifest = manifest or {"traces": {}}

    def build(self, reports_root):
        self.log.append(("manifest", Path(reports_root)))
        return self.manifest


class HtmlStub:
    def __init__(self, log, output):
        self.log = log
        self.output = output

    def save_report(self, session_inputs, manifest):
        self.log.append(("html", session_inputs, manifest))
        return self.output


def make_service(handlers, log):
    return SessionProcessorService(
        handlers=handlers,
        adapter=AdapterStub(log),
        summary_service=SummaryStub(log, Path("reports/test_session_summary.txt")),
        manifest_service=ManifestStub(log),
        html_service=HtmlStub(log, Path("reports/test_session_summary.html")),
    )


def handler(name, log, result):
    def run(files):
        log.append((name, list(files)))
        return result
    return run


def test_processor_runs_only_supplied_blf_handler() -> None:
    log = []
    service = make_service(
        {
            "blf": handler("blf", log, {"source_file": "session.blf"}),
            "dlt": handler("dlt", log, {}),
        },
        log,
    )

    result = service.process(
        {
            "blf": [Path("data/blf/session.blf")],
            "dlt": [],
            "pcap": [],
            "mf4": [],
        }
    )

    assert result["processed_trace_types"] == ["blf"]
    assert [entry[0] for entry in log].count("blf") == 1
    assert not any(entry[0] == "dlt" for entry in log)


def test_processor_all_four_handlers_execute_in_deterministic_order() -> None:
    log = []
    handlers = {
        "mf4": handler("mf4", log, {"source_file": "session.MF4"}),
        "pcap": handler("pcap", log, {"analysis": {"capture": {"file_name": "session.pcap"}}}),
        "dlt": handler("dlt", log, {"capture": {"source_files": ["session.dlt"]}}),
        "blf": handler("blf", log, {"source_file": "session.blf"}),
    }
    service = make_service(handlers, log)

    result = service.process(
        {
            "mf4": [Path("data/MF4/session.MF4")],
            "pcap": [Path("data/pcap/session.pcap")],
            "dlt": [Path("data/dlt/session.dlt")],
            "blf": [Path("data/blf/session.blf")],
        }
    )

    assert result["processed_trace_types"] == ["blf", "dlt", "pcap", "mf4"]
    assert [entry[0] for entry in log[:4]] == ["blf", "dlt", "pcap", "mf4"]


def test_processor_rejects_zero_trace_input() -> None:
    service = SessionProcessorService(handlers={})

    with pytest.raises(ValueError, match="No supported traces were provided"):
        service.process({})


def test_processor_rejects_supplied_trace_without_handler_before_processing() -> None:
    log = []
    service = make_service({}, log)

    with pytest.raises(ValueError, match="No production handler is registered for: PCAP"):
        service.process({"pcap": [Path("data/pcap/session.pcap")]})

    assert log == []


def test_processor_rejects_non_dictionary_handler_result() -> None:
    log = []
    service = make_service(
        {"mf4": handler("mf4", log, ["not", "a", "dictionary"])},
        log,
    )

    with pytest.raises(TypeError, match="MF4 handler must return a dictionary"):
        service.process({"mf4": [Path("data/MF4/session.MF4")]})

    assert not any(entry[0] in {"adapter", "summary", "manifest", "html"} for entry in log)


def test_processor_handler_failure_prevents_summary_and_html_generation() -> None:
    log = []

    def failing_handler(files):
        log.append(("blf", list(files)))
        raise RuntimeError("analysis failed")

    service = make_service({"blf": failing_handler}, log)

    with pytest.raises(RuntimeError, match="analysis failed"):
        service.process({"blf": [Path("data/blf/session.blf")]})

    assert not any(entry[0] in {"adapter", "summary", "manifest", "html"} for entry in log)


def test_processor_generates_summary_before_manifest_and_html() -> None:
    log = []
    service = make_service(
        {"blf": handler("blf", log, {"source_file": "session.blf"})},
        log,
    )

    service.process({"blf": [Path("data/blf/session.blf")]})

    names = [entry[0] for entry in log]
    assert names.index("adapter") < names.index("summary")
    assert names.index("summary") < names.index("manifest")
    assert names.index("manifest") < names.index("html")


def test_processor_forwards_pcap_compound_outputs_to_adapter() -> None:
    log = []
    pcap_result = {
        "analysis": {"capture": {"file_name": "session.pcap"}},
        "din70121": {"selected_protocol": "DIN 70121"},
        "iso15118_tls": {"tls_version": "TLS 1.2"},
    }
    service = make_service(
        {"pcap": handler("pcap", log, pcap_result)},
        log,
    )

    service.process({"pcap": [Path("data/pcap/session.pcap")]})

    adapter_call = next(entry for entry in log if entry[0] == "adapter")
    kwargs = adapter_call[1]
    assert kwargs["pcap_analysis"] == pcap_result["analysis"]
    assert kwargs["din70121"] == pcap_result["din70121"]
    assert kwargs["iso15118_tls"] == pcap_result["iso15118_tls"]


def test_processor_sorts_paths_before_handler_invocation() -> None:
    log = []
    service = make_service(
        {"dlt": handler("dlt", log, {"capture": {"source_files": []}})},
        log,
    )

    service.process(
        {
            "dlt": [
                Path("data/dlt/z.dlt"),
                Path("data/dlt/a.dlt"),
            ]
        }
    )

    dlt_call = next(entry for entry in log if entry[0] == "dlt")
    assert dlt_call[1] == [Path("data/dlt/a.dlt"), Path("data/dlt/z.dlt")]
