import arrow

from ..base.time import BaseClock


class SystemClock(BaseClock):
    def utcnow(self) -> arrow.Arrow:
        return arrow.utcnow()
