from pathlib import Path

from readers.blf_reader import BlfReader
from services.blf_statistics_csv_service import (
    BlfStatisticsCsvService,
)
from services.blf_statistics_service import (
    BlfStatisticsService,
)


BLF_FILE = Path(
    r"data\blf\VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
)


def test_real_blf_statistics_csv(
    tmp_path: Path,
) -> None:

    trace = BlfReader().read(
        BLF_FILE,
    )

    statistics = (
        BlfStatisticsService()
        .analyze(trace)
    )

    csv_service = (
        BlfStatisticsCsvService()
    )

    temporary_output = (
        tmp_path / "statistics.csv"
    )

    result = csv_service.export(
        statistics,
        temporary_output,
    )

    assert result.exists()
    assert result.is_file()

    content = result.read_text(
        encoding="utf-8",
    )

    lines = content.splitlines()

    print()
    print(
        "Temporary Statistics CSV Path:",
        result,
    )
    print()

    print(
        "\n".join(
            lines[:15]
        )
    )

    assert "Metric,Value" in content
    assert "Total Frames,4110817" in content
