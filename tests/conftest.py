from pathlib import Path

import pytest


LEGACY_BLF_NAME = "VW316660436_BEUS_20251022_083710h_10242km_Trace.blf"
LEGACY_BLF_FILE = Path("data") / "blf" / LEGACY_BLF_NAME


def pytest_collection_modifyitems(config, items):
    if LEGACY_BLF_FILE.exists():
        return

    marker = pytest.mark.skip(
        reason=f"Optional legacy BLF fixture is not available: {LEGACY_BLF_FILE}"
    )
    for item in items:
        path = Path(str(item.path))
        if path.suffix.lower() != ".py":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        if LEGACY_BLF_NAME in text:
            item.add_marker(marker)
