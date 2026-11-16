from pathlib import Path

from readers.blf_reader import BlfReader
from readers.dlt_reader import DltReader
from readers.pcap_reader import PcapReader
from services.blf_charging_fault_correlation_service import BlfChargingFaultCorrelationService
from services.blf_inventory_report_service import BlfInventoryReportService
from services.blf_inventory_service import BlfInventoryService
from services.blf_statistics_report_service import BlfStatisticsReportService
from services.blf_statistics_service import BlfStatisticsService
from services.blf_signal_anomaly_service import BlfSignalAnomalyService
from services.blf_vehicle_inventory_extractor import BlfVehicleInventoryExtractor
from services.blf_vehicle_inventory_report_service import BlfVehicleInventoryReportService
from services.charging_analysis_service import ChargingAnalysisService
from services.din70121_report_service import Din70121ReportService
from services.dlt_analysis_service import DltAnalysisService
from services.dlt_report_service import DltReportService
from services.iso15118_tls_analysis_service import Iso15118TlsAnalysisService
from services.iso15118_tls_report_service import Iso15118TlsReportService
from services.mf4_charging_analysis_service import Mf4ChargingAnalysisService
from services.mf4_report_service import Mf4ReportService
from services.pcap_analysis_service import PcapAnalysisService
from services.pcap_report_service import PcapReportService


class SessionTraceHandlers:
    def __init__(
        self,
        dbc_file: Path = Path(
            r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc"
        ),
    ) -> None:
        self.dbc_file = Path(dbc_file)

    def build(self) -> dict:
        return {
            "blf": self.handle_blf,
            "dlt": self.handle_dlt,
            "pcap": self.handle_pcap,
            "mf4": self.handle_mf4,
        }

    def handle_blf(self, files: list[Path]) -> dict:
        self._require_exactly_one("BLF", files)
        blf_file = Path(files[0])
        if not self.dbc_file.exists():
            raise FileNotFoundError(f"DBC file not found: {self.dbc_file}")

        trace = BlfReader().read(blf_file)
        inventory = BlfInventoryService().analyze(trace)
        statistics = BlfStatisticsService().analyze(trace)
        vehicle_inventory = BlfVehicleInventoryExtractor().extract(
            trace,
            self.dbc_file,
        )
        charging = ChargingAnalysisService().analyze(
            blf_file=blf_file,
            dbc_file=self.dbc_file,
        )
        decoded_messages = charging.pop("_decoded_message_objects", [])
        signal_samples = charging.pop("_signal_samples", {})
        anomaly_analysis = BlfSignalAnomalyService().analyze(decoded_messages)
        heater_samples = list(signal_samples.get("KL_Fehler_HV_Heizer", []))
        charging_samples = {
            name: samples
            for name, samples in signal_samples.items()
            if name != "KL_Fehler_HV_Heizer"
        }
        charging_fault_correlation = None
        if heater_samples:
            charging_fault_correlation = BlfChargingFaultCorrelationService().correlate(
                fault_signal="KL_Fehler_HV_Heizer",
                fault_samples=heater_samples,
                charging_samples=charging_samples,
            )
            anomaly_analysis["primary_fault_summary"] = self._fault_summary(
                "KL_Fehler_HV_Heizer",
                heater_samples,
            )

        BlfInventoryReportService().save_report(
            inventory,
            blf_file.stem,
        )
        BlfStatisticsReportService().save_report(
            statistics,
            blf_file.stem,
        )
        BlfVehicleInventoryReportService().save_report(
            vehicle_inventory,
            str(blf_file),
            blf_inventory=inventory,
            statistics=statistics,
            charging_analysis=charging,
            anomaly_analysis=anomaly_analysis,
            charging_fault_correlation=charging_fault_correlation,
        )

        vin = getattr(getattr(vehicle_inventory, "vehicle", None), "vin", None)
        result = {
            "source_file": str(blf_file),
            "charging_progression": self._blf_charging_progression(charging),
            "connector_recognition": self._blf_connector_recognition(charging),
            "control_pilot_recognition": self._blf_control_pilot_recognition(charging),
            "root_cause_status": "UNCONFIRMED",
            "fault_findings": list(charging.get("findings", [])),
            "charging_analysis": charging,
            "anomaly_analysis": anomaly_analysis,
            "charging_fault_correlation": charging_fault_correlation,
        }
        if vin:
            result["vehicle_identity"] = {
                "vin": vin,
                "status": "CONFIRMED",
                "source": "BLF / VIN_01",
            }
        return result

    def handle_dlt(self, files: list[Path]) -> dict:
        if not files:
            raise ValueError("DLT handler requires at least one trace")
        reader = DltReader()
        traces = [reader.read(Path(path)) for path in files]
        analysis = DltAnalysisService().analyze(traces)
        DltReportService().generate(analysis)
        return analysis

    def handle_pcap(self, files: list[Path]) -> dict:
        if not files:
            raise ValueError("PCAP handler requires at least one trace")

        captures = []
        din_reports = []
        tls_analyses = []
        tls_reports = []

        for path in files:
            pcap_path = Path(path)
            trace = PcapReader().read(pcap_path)
            analysis = PcapAnalysisService().analyze(trace)
            PcapReportService(
                output_directory=Path("reports") / "pcap" / pcap_path.stem
            ).generate(analysis)

            capture = {
                "source_file": str(pcap_path),
                "analysis": analysis,
            }

            din_path = Din70121ReportService(
                output_dir=Path("reports") / "pcap" / "din70121" / pcap_path.stem
            ).generate(pcap_path)
            din_reports.append({"source_file": str(pcap_path), "report": str(din_path)})
            capture["din70121_report"] = str(din_path)

            tls_analysis = Iso15118TlsAnalysisService().analyze(pcap_path)
            tls_analyses.append({"source_file": str(pcap_path), "analysis": tls_analysis})
            tls_output = Path("reports") / "pcap" / "iso15118" / pcap_path.stem
            tls_report = Iso15118TlsReportService().generate(
                pcap_path,
                output_dir=tls_output,
            )
            tls_reports.append({"source_file": str(pcap_path), "report": str(tls_report)})
            capture["iso15118_tls"] = tls_analysis
            captures.append(capture)

        return {
            "analysis": self._pcap_session_analysis(captures),
            "din70121": self._din70121_session_result(din_reports),
            "iso15118_tls": self._tls_session_result(tls_analyses, tls_reports),
            "captures": captures,
        }

    def handle_mf4(self, files: list[Path]) -> dict:
        self._require_exactly_one("MF4", files)
        mf4_file = Path(files[0])
        analysis = Mf4ChargingAnalysisService().analyze(mf4_file)
        Mf4ReportService().save_report(analysis)
        return analysis

    def _fault_summary(self, signal_name: str, samples: list[dict]) -> dict:
        ordered = sorted(samples, key=lambda sample: sample["timestamp"])
        intervals = 0
        recoveries = 0
        active = False
        first_timestamp = None
        last_timestamp = None
        abnormal_values = {"Fehler"}
        normal_values = {
            "Kein HV Fehler am HV Heizer erkannt",
            "Kein HV Fehler am EKK erkannt",
        }
        for sample in ordered:
            value = str(sample.get("value"))
            if value in abnormal_values and not active:
                active = True
                intervals += 1
                first_timestamp = first_timestamp or sample.get("timestamp")
            elif value in normal_values and active:
                active = False
                recoveries += 1
            last_timestamp = sample.get("timestamp")
        return {
            "signal_name": signal_name,
            "fault_value": "Fehler",
            "fault_intervals": intervals,
            "recoveries": recoveries,
            "active_at_trace_end": active,
            "first_timestamp": first_timestamp,
            "last_timestamp": last_timestamp,
            "charging_causal_status": "UNCONFIRMED",
        }

    def _require_exactly_one(self, trace_type: str, files: list[Path]) -> None:
        if len(files) != 1:
            raise ValueError(
                f"{trace_type} handler currently requires exactly one trace; "
                f"received {len(files)}"
            )

    def _blf_charging_progression(self, charging: dict) -> str:
        values = charging.get("signal_values", {})
        if values.get("HVLM_Ladevorgang_Anf") == "Laden_nicht_angefordert":
            return "NOT_OBSERVED"
        return "INDETERMINATE"

    def _blf_connector_recognition(self, charging: dict) -> str:
        values = charging.get("signal_values", {})
        connector_keys = (
            "HVLM_Steckerstatus_A",
            "HVLM_Steckerstatus_B",
            "STK_Stecker_Status",
            "HVLS_GBT_DcSteckerStatus",
        )
        observed = [str(values[key]) for key in connector_keys if key in values]
        negative = {
            "kein_Stecker_erkannt",
            "nicht_erkannt",
            "Init",
        }
        if observed and all(value in negative for value in observed):
            return "NOT_RECOGNIZED"
        return "INDETERMINATE"
    def _blf_control_pilot_recognition(self, charging: dict) -> str:
        values = charging.get("signal_values", {})
        status = str(values.get("HVLS_CP_Status_A", ""))
        frequency = str(values.get("HVLS_CP_Frequenz_A", ""))
        states = {
            str(values[key])
            for key in ("HVLM_CP_State_A", "HVLM_CP_State_B")
            if key in values
        }
        if status == "CP_nicht_erkannt":
            return "NOT_ESTABLISHED"
        if frequency == "keine_Frequenz_erkannt" and states and states.issubset(
            {"A", "Init", "kein_Zustand_erkannt"}
        ):
            return "NOT_ESTABLISHED"
        readiness = {
            str(values[key])
            for key in ("HVLM_CDO_LadebereitFzg", "HVLM_CJ_LadebereitschaftFzg")
            if key in values
        }
        if readiness.intersection({"keine_Ladebereitschaft", "not_ready"}):
            return "NOT_ESTABLISHED"
        return "INDETERMINATE"
    def _din70121_session_result(self, reports: list[dict]) -> dict:
        messages = (
            "SessionSetup",
            "ServiceDiscovery",
            "ServicePaymentSelection",
            "ContractAuthentication",
            "ChargeParameterDiscovery",
            "CableCheck",
            "PreCharge",
            "PowerDelivery",
            "CurrentDemand",
            "WeldingDetection",
            "SessionStop",
        )
        combined = []
        for item in reports:
            report = Path(str(item.get("report", "")))
            directory = report.parent if report.suffix else report
            if directory.exists():
                for path in sorted(directory.glob("*.txt")):
                    combined.append(path.read_text(encoding="utf-8", errors="replace"))
        text = "\n".join(combined)
        observed = [message for message in messages if message.lower() in text.lower()]
        result = {
            "capture_count": len(reports),
            "captures": reports,
            "analysis_status": "OBSERVED" if observed else "NOT_OBSERVED",
        }
        if "din 70121" in text.lower() or observed:
            result["selected_protocol"] = "DIN 70121"
        if observed:
            result["furthest_message"] = observed[-1]
            result["message_count"] = len(observed)
            result["session_completion"] = "OBSERVED" if "SessionStop" in observed else "NOT_OBSERVED"
        return result

    def _tls_session_result(self, analyses: list[dict], reports: list[dict]) -> dict:
        flattened = []
        for item in analyses:
            self._flatten_values(item.get("analysis"), flattened)
        text = " ".join(str(value) for _, value in flattened)
        lower = text.lower()
        version = next((value for value in ("TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0") if value.lower() in lower), None)
        server_certificate = self._evidence_present(flattened, ("server", "cert")) or self._evidence_present(flattened, ("certificates",))
        client_certificate = self._evidence_present(flattened, ("client", "cert"))
        observed = bool(version or server_certificate or "client hello" in lower or "server hello" in lower)
        result = {
            "capture_count": len(analyses),
            "captures": analyses,
            "reports": reports,
            "analysis_status": "OBSERVED" if observed else "NOT_OBSERVED",
            "server_certificate_observed": server_certificate,
            "client_certificate_observed": client_certificate,
        }
        if version:
            result["tls_version"] = version
        return result

    def _flatten_values(self, value, target: list, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                self._flatten_values(child, target, path)
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                self._flatten_values(child, target, f"{prefix}[{index}]")
        else:
            target.append((prefix.lower(), value))

    def _evidence_present(self, flattened: list, terms: tuple[str, ...]) -> bool:
        for path, value in flattened:
            if all(term in path for term in terms):
                if isinstance(value, bool):
                    if value:
                        return True
                elif value not in (None, "", 0, "NOT_OBSERVED", "not observed"):
                    return True
        return False

    def _pcap_session_analysis(self, captures: list[dict]) -> dict:
        protocol_counts = {}
        packet_count = 0
        source_files = []
        for item in captures:
            analysis = item["analysis"]
            capture = analysis.get("capture", {})
            source_files.append(item["source_file"])
            packet_count += int(capture.get("packet_count", 0) or 0)
            for protocol, count in analysis.get("protocol_counts", {}).items():
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + count
        return {
            "capture": {
                "file_name": f"{len(captures)} PCAP captures",
                "file_path": source_files[0] if len(source_files) == 1 else "multiple PCAP captures",
                "packet_count": packet_count,
                "source_files": source_files,
            },
            "protocol_counts": protocol_counts,
            "vlan_counts": {},
            "transition_analysis": {},
        }
