from pathlib import Path

from readers.asc_reader import AscReader
from services.asc_dbc_decoder_service import AscDbcDecoderService
from services.asc_dbc_inspection_report_service import AscDbcInspectionReportService


ASC_FILES = sorted(Path("data/asc").glob("*.asc"))
DBC_FILE = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")

if not ASC_FILES:
    raise SystemExit("No ASC file found in data/asc")
if not DBC_FILE.exists():
    raise SystemExit(f"DBC file not found: {DBC_FILE}")
if len(ASC_FILES) != 1:
    raise SystemExit(f"Expected exactly one ASC file for inspection; found {len(ASC_FILES)}")

trace = AscReader().read(ASC_FILES[0])
analysis = AscDbcDecoderService().decode(trace, DBC_FILE)
output = AscDbcInspectionReportService().generate(
    analysis,
    Path("reports/asc/asc_dbc_inspection.txt"),
)
print(output.resolve())
