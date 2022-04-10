import arrow


# TODO: make abstract
class Clock:
    pass


class SystemClock(Clock):

    @staticmethod
    def utcnow():
        return arrow.utcnow()
