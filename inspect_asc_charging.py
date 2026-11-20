from pathlib import Path

from readers.asc_reader import AscReader
from services.asc_charging_analysis_service import AscChargingAnalysisService
from services.asc_charging_inspection_report_service import AscChargingInspectionReportService
from services.asc_dbc_decoder_service import AscDbcDecoderService


ASC_FILES = sorted(Path("data/asc").glob("*.asc"))
DBC_FILE = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")

if not ASC_FILES:
    raise SystemExit("No ASC file found in data/asc")
if len(ASC_FILES) != 1:
    raise SystemExit(f"Expected exactly one ASC file for inspection; found {len(ASC_FILES)}")
if not DBC_FILE.exists():
    raise SystemExit(f"DBC file not found: {DBC_FILE}")

trace = AscReader().read(ASC_FILES[0])
dbc_analysis = AscDbcDecoderService().decode(
    trace,
    DBC_FILE,
    target_signals=AscChargingAnalysisService.TARGET_SIGNALS,
)
charging_analysis = AscChargingAnalysisService().analyze(dbc_analysis)
output = AscChargingInspectionReportService().generate(
    charging_analysis,
    Path("reports/asc/asc_charging_inspection.txt"),
)
print(output.resolve())
