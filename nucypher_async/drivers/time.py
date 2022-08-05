import arrow

from ..base.time import BaseClock


class SystemClock(BaseClock):

    @staticmethod
    def utcnow() -> arrow.Arrow:
        return arrow.utcnow()
