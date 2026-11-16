# ev_trace_processor

Python engineering framework for analysis and correlation of automotive trace data across BLF, DLT, PCAP, and MF4 inputs.

## Overview

ev_trace_processor analyzes each supported trace type independently, preserves trace-specific evidence and provenance, and can combine available results into a session-level engineering summary.

Supported trace types:

- BLF: CAN/CAN-FD analysis with DBC decoding, charging-state analysis, signal anomaly detection, vehicle inventory extraction, and fault correlation.
- DLT: diagnostic log analysis, statistics, and software/vehicle inventory extraction.
- PCAP: HomePlug/IoTecha embedded-frame inspection, IPv6/UDP/TCP/V2GTP recovery, DIN 70121 analysis, ISO 15118/TLS analysis, and certificate metadata reporting.
- MF4: measurement-channel inventory, charging-related signal discovery, charging-state/prerequisite analysis, and engineering reporting.

A session may contain any non-empty subset of these supported trace types. Only supplied traces are analyzed and included in the session summary.

## Analysis Model

The project follows a two-level analysis model:

1. Per-trace analysis
   - Each BLF, DLT, PCAP, or MF4 input is processed independently.
   - Reports retain the source trace and trace-specific provenance.
   - Multiple PCAP captures remain individually identifiable.

2. Session-level synthesis
   - Per-trace evidence is adapted into a common session evidence model.
   - Results are correlated without discarding their original source.
   - Session summaries present combined engineering evidence while keeping trace provenance explicit.

When multiple traces are deliberately loaded together, the processor treats them as belonging to the same intended test session unless independent evidence indicates otherwise. This assumption does not by itself prove vehicle identity.

## VIN Handling

VIN evidence is reported only when independently extracted from a trace that supports VIN extraction.

Current BLF processing can obtain VIN evidence from the configured CAN/DBC signal path. Session membership alone is not used to assign a VIN to DLT, PCAP, or MF4 evidence.

## BLF Capabilities

BLF processing includes:

- CAN/CAN-FD trace reading
- DBC-based decoding
- targeted charging-signal extraction
- charging prerequisite analysis
- charging-state progression analysis
- charging timeline reconstruction
- vehicle-wide signal anomaly detection
- charging-to-fault correlation
- vehicle inventory extraction
- VIN extraction when independently observed
- statistics and engineering reports
- human-readable engineering value formatting

## DLT Capabilities

DLT processing includes:

- DLT trace analysis
- message/event statistics
- diagnostic evidence extraction
- software inventory extraction
- vehicle software inventory support
- analysis, inventory, statistics, and case-summary reporting
- integration into session-level evidence

## PCAP Capabilities

PCAP processing supports protocol and charging-communication investigation across raw and embedded network captures.

Capabilities include:

- PCAP inventory and statistics
- IoTecha embedded-frame classification
- HomePlug/HPGP frame analysis
- IPv6 recovery from supported embedded layouts
- UDP/TCP inspection
- SDP/V2G communication inspection
- V2GTP payload recovery
- pure-Python V2G EXI inspection for implemented message families
- DIN 70121 captured-vector identification and reporting
- ISO 15118/TLS session analysis
- TLS handshake evidence
- certificate metadata and fingerprint reporting
- per-capture provenance
- per-capture HTML navigation and detailed reports

Certificate analysis is intentionally metadata-oriented. Private keys and full sensitive certificate material are not required for normal reporting.

### DIN 70121

The current DIN 70121 path includes captured-vector identification for implemented charging-session messages, including the supported protocol negotiation and message families developed for the project. General standards-complete EXI decoding is not implied where a message is only identified through validated captured-vector or sequence-correlated evidence.

### ISO 15118 / TLS

TLS analysis reports observed handshake evidence, protocol information available from the capture, certificate-chain metadata, and relevant authentication observations. Reports distinguish confirmed evidence from information that was not observed or remains indeterminate.

## MF4 Capabilities

MF4 processing includes:

- channel inventory
- charging-related channel discovery
- charging prerequisite analysis
- charging progression assessment
- engineering analysis report generation
- case-summary generation
- integration into session-level evidence

The project uses `asammdf` for MF4 processing.

## Session Processing

The session layer is implemented around the production session services, including:

- `services/session_trace_handlers.py`
- `services/session_evidence_adapter.py`
- `services/session_processor_service.py`
- `services/session_summary_service.py`
- `services/session_html_report_service.py`
- `services/session_report_manifest.py`
- `services/detail_html_report_service.py`

The processor supports BLF, DLT, PCAP, and MF4 independently or in combinations. At least one supported trace input is required.

Session reports include only the trace families that were actually supplied and successfully analyzed.

## Reports

Generated reports are written under `reports/` and are intentionally excluded from Git.

The current report families are organized approximately as:

```text
reports/
    blf/
    dlt/
    mf4/
    pcap/
        <per-capture>/
        din70121/
        iso15118/
    test_session_summary.html
    test_session_summary.txt
```

BLF, DLT, PCAP, DIN 70121, ISO 15118/TLS, MF4, and session reporting use human-readable engineering formatting. HTML reports provide detailed navigation where applicable.

Generated reports should be reproduced from source traces rather than committed to the repository.

## Project Structure

```text
ev_trace_processor/
    config/             configuration
    data/               local trace/test data; not committed
    dbc/                local DBC databases; DBC files are not committed
    docs/               project documentation
    inspection/         engineering and protocol inspection utilities
    models/             shared data models
    readers/            trace/data readers
    reports/            generated reports; not committed
    services/           production analysis and reporting services
    tests/              unit, integration, and real-trace regression tests

    main.py
    generate_pcap_landing_pages.py
    regenerate_blf_case_summary.py
    regenerate_mf4_case_summary.py
    regenerate_session_html.py
    requirements.txt
    README.md
```

## Inspection Utilities

Exploratory and forensic utilities belong under `inspection/`, not in the repository root.

Run inspection modules from the repository root using Python module mode:

```bat
python -m inspection.inspect_pcap_app_protocol_sequence
```

For a new utility named:

```text
inspection/inspect_example.py
```

run:

```bat
python -m inspection.inspect_example
```

New inspection utilities should follow this convention.

## Local Data Policy

Raw trace data is intentionally excluded from Git through `.gitignore`.

The repository ignores the complete:

```text
data/
reports/
```

folders as well as common trace extensions such as BLF, MF4, DLT, and PCAP. DBC files are also excluded.

This keeps large vehicle traces, generated reports, and capture-derived evidence out of source control.

## Installation

Create or activate the desired Python environment, then install the project dependencies:

```bat
python -m pip install -r requirements.txt
```

MF4 support requires the `asammdf` dependency listed by the project requirements.

## Running the Processor

Run the main application from the repository root:

```bat
python main.py
```

The current `main.py` wiring invokes the production trace/session processing path and generates the applicable outputs for the available supported inputs.

## Report Regeneration Utilities

Reusable report-regeneration utilities intentionally remain in the repository root.

Examples:

```bat
python regenerate_blf_case_summary.py
python regenerate_mf4_case_summary.py
python regenerate_session_html.py
python generate_pcap_landing_pages.py
```

These are repeatable utilities, unlike temporary source-patching scripts used during development.

## Testing

Run the complete regression suite from the repository root:

```bat
python -m pytest
```

Run an individual test module with:

```bat
python -m pytest tests\test_session_processor_service.py -v
```

The test suite includes unit tests, service-level regression tests, subset/session integration tests, and real-trace tests for the supported trace families where local test data is available.

Because raw trace data is not committed, real-trace tests require the expected local files under `data/`.

## Engineering Evidence Principles

The reporting and session layers follow several important evidence rules:

- preserve the source trace for each conclusion
- do not infer VIN merely because files were loaded in the same session
- distinguish observed evidence from interpretation
- distinguish confirmed, not-observed, and indeterminate conditions where appropriate
- do not convert missing evidence into a positive conclusion
- keep separate PCAP captures individually attributable
- preserve trace-specific reports even when producing a combined session summary
- use human-readable engineering labels without changing the underlying decoded evidence

## Development Conventions

- Production analysis code belongs under `services/`.
- Data models belong under `models/`.
- Tests belong under `tests/`.
- Exploratory trace/protocol tools belong under `inspection/`.
- Repeatable report-regeneration utilities may remain in the repository root.
- Raw traces and generated reports stay local and are not committed.
- Temporary one-time patch or migration scripts should be removed after their changes are integrated and verified.

## Current Scope

ev_trace_processor is an engineering trace-analysis framework, not a standards-complete implementation of every automotive protocol encountered in a capture. Conclusions should remain bounded by the evidence actually decoded or validated from each trace.

The project is designed to grow incrementally: new decoders, trace handlers, evidence adapters, tests, and report views should preserve the same source-provenance and regression-testing principles.
