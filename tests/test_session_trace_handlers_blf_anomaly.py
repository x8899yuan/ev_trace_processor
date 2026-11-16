from pathlib import Path

import services.session_trace_handlers as module
from services.session_trace_handlers import SessionTraceHandlers


class Trace:
    pass


class Vehicle:
    vin = "1V2ZZZE81TC000011"


class Inventory:
    vehicle = Vehicle()


def test_blf_handler_runs_and_forwards_vehicle_signal_anomaly_analysis(monkeypatch, tmp_path: Path) -> None:
    blf = tmp_path / "trace.blf"
    dbc = tmp_path / "trace.dbc"
    blf.write_bytes(b"blf")
    dbc.write_text("dbc", encoding="utf-8")
    decoded = [object(), object()]
    anomaly = {"anomaly_count": 1, "anomalies": [{"signal_name": "KL_Fehler_HV_Heizer"}]}
    captured = {}

    monkeypatch.setattr(module.BlfReader, "read", lambda self, path: Trace())
    monkeypatch.setattr(module.BlfInventoryService, "analyze", lambda self, trace: object())
    monkeypatch.setattr(module.BlfStatisticsService, "analyze", lambda self, trace: object())
    monkeypatch.setattr(module.BlfVehicleInventoryExtractor, "extract", lambda self, trace, dbc_file: Inventory())
    monkeypatch.setattr(
        module.ChargingAnalysisService,
        "analyze",
        lambda self, **kwargs: {
            "_decoded_message_objects": decoded,
            "_signal_samples": {"x": []},
            "signal_values": {},
            "findings": [],
        },
    )
    monkeypatch.setattr(module.BlfSignalAnomalyService, "analyze", lambda self, messages: anomaly if messages == decoded else None)
    monkeypatch.setattr(module.BlfInventoryReportService, "save_report", lambda *args, **kwargs: tmp_path / "inventory.txt")
    monkeypatch.setattr(module.BlfStatisticsReportService, "save_report", lambda *args, **kwargs: tmp_path / "statistics.txt")

    def save_report(self, *args, **kwargs):
        captured.update(kwargs)
        return tmp_path / "blf_analysis_report.txt"

    monkeypatch.setattr(module.BlfVehicleInventoryReportService, "save_report", save_report)

    result = SessionTraceHandlers(dbc_file=dbc).handle_blf([blf])

    assert captured["anomaly_analysis"] == anomaly
    assert result["anomaly_analysis"] == anomaly
    assert "_decoded_message_objects" not in result["charging_analysis"]
    assert "_signal_samples" not in result["charging_analysis"]
