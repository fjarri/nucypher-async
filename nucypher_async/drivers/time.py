import arrow

from ..base import Clock


class SystemClock(Clock):

    @staticmethod
    def utcnow() -> arrow.Arrow:
        return arrow.utcnow()
