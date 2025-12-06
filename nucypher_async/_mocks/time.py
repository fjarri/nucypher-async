import arrow
import trio

from ..base.time import BaseClock


class MockClock(BaseClock):
    def __init__(self) -> None:
        self._start: float | None = None

    def utcnow(self) -> arrow.Arrow:
        try:
            trio_time = trio.current_time()
        except RuntimeError:
            trio_time = None
        real_time = arrow.utcnow()

        if self._start is None and trio_time is not None:
            # Switching to Trio `autojump_clock` time
            self._start = real_time.timestamp() - trio_time
        elif self._start is not None and trio_time is None:
            # This will lead to going back in time
            raise RuntimeError(
                "MockClock cannot be used again in real time after being used in `trio` context"
            )

        if self._start is not None and trio_time is not None:
            return arrow.get(self._start + trio_time)

        return real_time
