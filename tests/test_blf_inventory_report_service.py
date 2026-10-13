from datetime import datetime

from models.blf_inventory import (
    BlfInventory,
    CanIdStatistic,
)
from services.blf_inventory_report_service import (
    BlfInventoryReportService,
)


def create_inventory() -> BlfInventory:

    return BlfInventory(
        total_frames=1000,
        unique_can_ids=3,
        standard_frame_count=900,
        extended_frame_count=100,
        channels=[1, 7],
        start_timestamp=datetime(
            2025,
            1,
            1,
            0,
            0,
            0,
        ),
        end_timestamp=datetime(
            2025,
            1,
            1,
            0,
            0,
            10,
        ),
        can_id_statistics=[
            CanIdStatistic(
                arbitration_id=0x187,
                frame_count=500,
                channel=7,
                is_extended_id=False,
            ),
            CanIdStatistic(
                arbitration_id=0x100,
                frame_count=300,
                channel=7,
                is_extended_id=False,
            ),
            CanIdStatistic(
                arbitration_id=0x200,
                frame_count=200,
                channel=1,
                is_extended_id=True,
            ),
        ],
    )


def test_generate_report_returns_string() -> None:

    report = (
        BlfInventoryReportService()
        .generate_report(
            create_inventory()
        )
    )

    assert isinstance(
        report,
        str,
    )


def test_report_contains_total_frames() -> None:

    report = (
        BlfInventoryReportService()
        .generate_report(
            create_inventory()
        )
    )

    assert "1,000" in report


def test_report_contains_unique_can_ids() -> None:

    report = (
        BlfInventoryReportService()
        .generate_report(
            create_inventory()
        )
    )

    assert "3" in report


def test_report_contains_channels() -> None:

    report = (
        BlfInventoryReportService()
        .generate_report(
            create_inventory()
        )
    )

    assert "[1, 7]" in report


def test_report_contains_top_can_id() -> None:

    report = (
        BlfInventoryReportService()
        .generate_report(
            create_inventory()
        )
    )

    assert "0x187" in report


def test_report_contains_frame_count() -> None:

    report = (
        BlfInventoryReportService()
        .generate_report(
            create_inventory()
        )
    )

    assert "500" in report


def test_report_orders_can_ids_by_frame_count() -> None:

    report = (
        BlfInventoryReportService()
        .generate_report(
            create_inventory()
        )
    )

    position_187 = report.index(
        "0x187"
    )

    position_100 = report.index(
        "0x100"
    )

    assert position_187 < position_100


def test_top_count_limit() -> None:

    report = (
        BlfInventoryReportService()
        .generate_report(
            create_inventory(),
            top_count=2,
        )
    )

    assert "0x187" in report
    assert "0x100" in report
    assert "0x200" not in report