from pathlib import Path

import cantools
from cantools.database import Database
from cantools.database.can import Message


class DbcService:
    def load(
        self,
        dbc_file: Path,
    ) -> Database:
        if not dbc_file.exists():
            raise FileNotFoundError(
                f"DBC file not found: {dbc_file}"
            )

        return cantools.database.load_file(
            str(dbc_file)
        )

    def message_count(
        self,
        dbc_file: Path,
    ) -> int:
        database = self.load(
            dbc_file
        )

        return len(
            database.messages
        )

    def signal_count(
        self,
        dbc_file: Path,
    ) -> int:
        database = self.load(
            dbc_file
        )

        return sum(
            len(message.signals)
            for message in database.messages
        )

    def message_names(
        self,
        dbc_file: Path,
    ) -> list[str]:
        database = self.load(
            dbc_file
        )

        return [
            message.name
            for message in database.messages
        ]

    def get_message(
        self,
        dbc_file: Path,
        message_name: str,
    ) -> Message:
        database = self.load(
            dbc_file
        )

        return database.get_message_by_name(
            message_name
        )
