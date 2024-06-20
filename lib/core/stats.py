from datetime import datetime

__all__ = ["Stats"]


class Stats:
    """
    Holds application counters and timestamps
    """

    def __init__(self, start_time: datetime = None):
        self.start_time = start_time or datetime.utcnow()
        self.count_input = 0
        self.count_good = 0
        self.count_error = 0

    def dict(self, stopped: datetime | None = None) -> dict:
        stopped = stopped or datetime.utcnow()
        return {
            "duration": (stopped - self.start_time).total_seconds(),
            "valid targets": self.count_input,
            "success": self.count_good,
            "fails": self.count_error,
        }
