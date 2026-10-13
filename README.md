ev_trace_processor
EV trace analysis framework for CAN decoding, charging diagnostics, and root-cause analysis.

Overview
ev_trace_processor is a Python-based engineering analysis framework designed to process vehicle CAN trace data and automate charging diagnostics.

The application:

Reads vehicle trace data from BLF files
Decodes CAN messages using DBC databases
Extracts charging-related signals
Reconstructs charging timelines
Detects charging events
Performs root-cause analysis
Generates engineering diagnostic reports
Generates charging case summaries
Features
BLF trace file processing
DBC-based CAN decoding
Charging event detection
Charging timeline reconstruction
Signal extraction
Root-cause analysis
Automated engineering reports
Automated case summaries
Project Structure
ev_trace_processor/
├── readers/
├── services/
├── tests/
├── dbc/
├── data/
├── reports/
├── main.py
└── README.md