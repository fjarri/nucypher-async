import arrow
import trio

from ..base import Clock


class MockClock(Clock):

    def __init__(self):
        self._start = arrow.utcnow().timestamp() - trio.current_time()

    def utcnow(self) -> arrow.Arrow:
        return arrow.get(self._start + trio.current_time())
