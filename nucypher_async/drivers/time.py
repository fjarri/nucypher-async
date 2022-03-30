import arrow


class Clock:

    @staticmethod
    def utcnow():
        return arrow.utcnow()
