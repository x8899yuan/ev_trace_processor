from pathlib import Path

import pytest

from services.session_processor_service import TestSessionProcessorService as SessionProcessorService


RUN_ID = "20261118111230"


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

    def save_summary(self, run_id=None, **session_inputs):
        self.log.append(("summary", run_id, session_inputs))
        return self.output


class DetailHtmlStub:
    def __init__(self, log):
        self.log = log

    def generate_all(self, reports_root, run_id=None):
        self.log.append(("detail_html", Path(reports_root), run_id))
        return []


class ManifestStub:
    def __init__(self, log, manifest=None):
        self.log = log
        self.manifest = manifest or {"traces": {}}

    def build(self, reports_root, run_id=None):
        self.log.append(("manifest", Path(reports_root), run_id))
        return self.manifest


class HtmlStub:
    def __init__(self, log, output):
        self.log = log
        self.output = output

    def save_report(self, session_inputs, manifest, run_id=None):
        self.log.append(("html", run_id, session_inputs, manifest))
        return self.output


def make_service(handlers, log):
    return SessionProcessorService(
        handlers=handlers,
        adapter=AdapterStub(log),
        summary_service=SummaryStub(log, Path(f"reports/session_summary_{RUN_ID}.txt")),
        detail_html_service=DetailHtmlStub(log),
        manifest_service=ManifestStub(log),
        html_service=HtmlStub(log, Path(f"reports/session_summary_{RUN_ID}.html")),
    )


def handler(name, log, result):
    def run(files):
        log.append((name, list(files)))
        return result
    return run


def process(service, discovered):
    return service.process(discovered, run_id=RUN_ID)


def test_processor_runs_only_supplied_blf_handler():
    log = []
    service = make_service({"blf": handler("blf", log, {"source_file": "session.blf"}), "dlt": handler("dlt", log, {})}, log)
    result = process(service, {"blf": [Path("data/blf/session.blf")], "dlt": [], "pcap": [], "mf4": []})
    assert result["run_id"] == RUN_ID
    assert result["processed_trace_types"] == ["blf"]
    assert [entry[0] for entry in log].count("blf") == 1
    assert not any(entry[0] == "dlt" for entry in log)


def test_processor_all_four_handlers_execute_in_deterministic_order():
    log = []
    handlers = {
        "mf4": handler("mf4", log, {"source_file": "session.MF4"}),
        "pcap": handler("pcap", log, {"analysis": {"capture": {"file_name": "session.pcap"}}}),
        "dlt": handler("dlt", log, {"capture": {"source_files": ["session.dlt"]}}),
        "blf": handler("blf", log, {"source_file": "session.blf"}),
    }
    result = process(make_service(handlers, log), {
        "mf4": [Path("data/MF4/session.MF4")], "pcap": [Path("data/pcap/session.pcap")],
        "dlt": [Path("data/dlt/session.dlt")], "blf": [Path("data/blf/session.blf")],
    })
    assert result["processed_trace_types"] == ["blf", "dlt", "pcap", "mf4"]
    assert [entry[0] for entry in log[:4]] == ["blf", "dlt", "pcap", "mf4"]


def test_processor_rejects_zero_trace_input():
    with pytest.raises(ValueError, match="No supported traces were provided"):
        SessionProcessorService(handlers={}).process({}, run_id=RUN_ID)


def test_processor_rejects_invalid_run_id():
    with pytest.raises(ValueError, match="YYYYMMDDHHMMSS"):
        SessionProcessorService(handlers={}).process({}, run_id="2026-11-18")


def test_processor_rejects_supplied_trace_without_handler_before_processing():
    log = []
    with pytest.raises(ValueError, match="No production handler is registered for: PCAP"):
        process(make_service({}, log), {"pcap": [Path("data/pcap/session.pcap")]})
    assert log == []


def test_processor_rejects_non_dictionary_handler_result():
    log = []
    service = make_service({"mf4": handler("mf4", log, ["not", "a", "dictionary"])}, log)
    with pytest.raises(TypeError, match="MF4 handler must return a dictionary"):
        process(service, {"mf4": [Path("data/MF4/session.MF4")]})
    assert not any(entry[0] in {"adapter", "summary", "manifest", "html"} for entry in log)


def test_processor_handler_failure_prevents_summary_and_html_generation():
    log = []
    def failing_handler(files):
        log.append(("blf", list(files)))
        raise RuntimeError("analysis failed")
    with pytest.raises(RuntimeError, match="analysis failed"):
        process(make_service({"blf": failing_handler}, log), {"blf": [Path("data/blf/session.blf")]})
    assert not any(entry[0] in {"adapter", "summary", "manifest", "html"} for entry in log)


def test_processor_propagates_run_id_and_generation_order():
    log = []
    service = make_service({"blf": handler("blf", log, {"source_file": "session.blf"})}, log)
    process(service, {"blf": [Path("data/blf/session.blf")]})
    names = [entry[0] for entry in log]
    assert names.index("adapter") < names.index("summary") < names.index("detail_html") < names.index("manifest") < names.index("html")
    assert next(entry for entry in log if entry[0] == "summary")[1] == RUN_ID
    assert next(entry for entry in log if entry[0] == "detail_html")[2] == RUN_ID
    assert next(entry for entry in log if entry[0] == "manifest")[2] == RUN_ID
    assert next(entry for entry in log if entry[0] == "html")[1] == RUN_ID


def test_processor_forwards_pcap_compound_outputs_to_adapter():
    log = []
    pcap_result = {"analysis": {"capture": {"file_name": "session.pcap"}}, "din70121": {"selected_protocol": "DIN 70121"}, "iso15118_tls": {"tls_version": "TLS 1.2"}}
    process(make_service({"pcap": handler("pcap", log, pcap_result)}, log), {"pcap": [Path("data/pcap/session.pcap")]})
    kwargs = next(entry for entry in log if entry[0] == "adapter")[1]
    assert kwargs["pcap_analysis"] == pcap_result["analysis"]
    assert kwargs["din70121"] == pcap_result["din70121"]
    assert kwargs["iso15118_tls"] == pcap_result["iso15118_tls"]


def test_processor_sorts_paths_before_handler_invocation():
    log = []
    service = make_service({"dlt": handler("dlt", log, {"capture": {"source_files": []}})}, log)
    process(service, {"dlt": [Path("data/dlt/z.dlt"), Path("data/dlt/a.dlt")]})
    assert next(entry for entry in log if entry[0] == "dlt")[1] == [Path("data/dlt/a.dlt"), Path("data/dlt/z.dlt")]
