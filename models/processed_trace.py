from dataclasses import dataclass, field

from models.trace_event import TraceEvent
from models.trace_metadata import TraceMetadata


@dataclass(slots=True)
class ProcessedTrace:
    """
    Represents a fully processed trace.

    Contains file metadata and the normalized events
    extracted from the trace.
    """

    metadata: TraceMetadata
    events: list[TraceEvent] = field(default_factory=list)

    @property
    def event_count(self) -> int:
        """
        Return the number of events.
        """
        return len(self.events)

    @property
    def is_empty(self) -> bool:
        """
        Return True if no events exist.
        """
        return len(self.events) == 0

    def add_event(self, event: TraceEvent) -> None:
        """
        Add a trace event.
        """
        self.events.append(event)

    def clear_events(self) -> None:
        """
        Remove all events.
        """
        self.events.clear()

    def to_dict(self) -> dict:
        """
        Convert the processed trace to a dictionary.
        """
        return {
            "metadata": self.metadata.to_dict(),
            "event_count": self.event_count,
            "events": [
                event.to_dict()
                for event in self.events
            ],
        }