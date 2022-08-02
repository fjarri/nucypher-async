from abc import ABC, abstractmethod

import arrow


class Clock(ABC):

    @staticmethod
    @abstractmethod
    def utcnow() -> arrow.Arrow:
        pass
