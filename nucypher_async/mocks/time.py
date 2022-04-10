import arrow
import trio


class MockClock:

    def __init__(self):
        self._start = arrow.utcnow().timestamp() - trio.current_time()

    def utcnow(self):
        return arrow.get(self._start + trio.current_time())
