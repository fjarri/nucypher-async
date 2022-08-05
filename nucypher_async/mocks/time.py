import arrow
import trio

from ..base.time import BaseClock


class MockClock(BaseClock):

    def __init__(self):
        self._start = arrow.utcnow().timestamp() - trio.current_time()

    def utcnow(self) -> arrow.Arrow:
        return arrow.get(self._start + trio.current_time())
