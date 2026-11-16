from pathlib import Path

from readers.blf_reader import BlfReader
from services.blf_charging_fault_correlation_service import BlfChargingFaultCorrelationService
from services.blf_inventory_service import BlfInventoryService
from services.blf_signal_anomaly_service import BlfSignalAnomalyService
from services.blf_statistics_service import BlfStatisticsService
from services.blf_vehicle_inventory_extractor import BlfVehicleInventoryExtractor
from services.blf_vehicle_inventory_report_service import BlfVehicleInventoryReportService
from services.charging_analysis_service import ChargingAnalysisService
from services.dbc_decoder_service import DbcDecoderService


BLF_FILE = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")
DBC_FILE = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")
FAULT_CAN_ID = 0x5E7
FAULT_SIGNAL = "KL_Fehler_HV_Heizer"
CHARGING_CAN_ID = 0x272
CHARGING_SIGNALS = (
    "HVLM_Ladevorgang_Anf",
    "HVLM_ZustandLadeablauf",
)


def main() -> None:
    trace = BlfReader().read(BLF_FILE)
    vehicle_inventory = BlfVehicleInventoryExtractor().extract(trace, DBC_FILE)
    blf_inventory = BlfInventoryService().analyze(trace)
    statistics = BlfStatisticsService().analyze(trace)
    charging_analysis = ChargingAnalysisService().analyze(BLF_FILE, DBC_FILE)

    reader = BlfReader()
    decoder = DbcDecoderService()
    anomaly_messages = []
    fault_samples = []
    charging_samples = {signal: [] for signal in CHARGING_SIGNALS}

    for event in reader.read_events(BLF_FILE):
        arbitration_id = event.payload.get("arbitration_id")
        data_hex = event.payload.get("data")
        if arbitration_id not in {FAULT_CAN_ID, CHARGING_CAN_ID} or not data_hex:
            continue
        try:
            decoded = decoder.decode_can_message(
                dbc_file=DBC_FILE,
                timestamp=event.timestamp.timestamp(),
                channel=event.payload.get("channel", 0),
                arbitration_id=arbitration_id,
                data=bytes.fromhex(data_hex),
            )
        except Exception:
            continue

        try:
            decoded.arbitration_id = arbitration_id
        except Exception:
            pass

        if arbitration_id == FAULT_CAN_ID:
            anomaly_messages.append(decoded)
            if FAULT_SIGNAL in decoded.signals:
                fault_samples.append(
                    {
                        "timestamp": decoded.timestamp,
                        "value": decoded.signals[FAULT_SIGNAL],
                    }
                )

        if arbitration_id == CHARGING_CAN_ID:
            for signal_name in CHARGING_SIGNALS:
                if signal_name in decoded.signals:
                    charging_samples[signal_name].append(
                        {
                            "timestamp": decoded.timestamp,
                            "value": decoded.signals[signal_name],
                        }
                    )

    anomaly_analysis = BlfSignalAnomalyService().analyze(anomaly_messages)
    anomaly_analysis["findings"] = [
        finding
        for finding in anomaly_analysis["findings"]
        if finding["signal"] == FAULT_SIGNAL
    ]
    anomaly_analysis["fault_count"] = sum(
        finding["severity"] == "FAULT"
        for finding in anomaly_analysis["findings"]
    )
    anomaly_analysis["warning_count"] = sum(
        finding["severity"] == "WARNING"
        for finding in anomaly_analysis["findings"]
    )

    correlation = BlfChargingFaultCorrelationService().correlate(
        fault_signal=FAULT_SIGNAL,
        fault_samples=fault_samples,
        charging_samples=charging_samples,
        abnormal_values={"Fehler"},
        normal_values={"Kein HV Fehler am HV Heizer erkannt"},
    )

    output = BlfVehicleInventoryReportService().save_report(
        vehicle_inventory,
        BLF_FILE.name,
        blf_inventory,
        statistics,
        charging_analysis,
        anomaly_analysis,
        correlation,
    )
    print(output)


if __name__ == "__main__":
    main()
