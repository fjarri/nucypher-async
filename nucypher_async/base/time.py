from abc import ABC, abstractmethod

import arrow


class BaseClock(ABC):
    """
    An abstract class for getting the current time.
    A behavior different from just returning the system time may be needed for tests.
    """

    # not a staticmethod since some implementations may need to maintain an internal state
    @abstractmethod
    def utcnow(self) -> arrow.Arrow:
        pass
