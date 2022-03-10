"""
This could be a separate library, but we're keeping it a submodule for now
for the ease of development.

Why not use standard library `logging`: it is stateful, and we want different behavior
depening on the environment (testing/usage as a library/running a server).
"""

from enum import IntEnum
import io
import time
import traceback
from typing import NamedTuple, List, Any, Tuple, Type, Optional
from pathlib import Path
import sys

import trio


class Level(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


_LEVEL_NAMES = {
    Level.DEBUG: 'debug',
    Level.INFO: 'info',
    Level.WARNING: 'warning',
    Level.ERROR: 'error',
    Level.CRITICAL: 'critical',
}


DEBUG = Level.DEBUG
INFO = Level.INFO
WARNING = Level.WARNING
ERROR = Level.ERROR
CRITICAL = Level.CRITICAL


class LogRecord(NamedTuple):
    timestamp: float
    logger_name: str
    level: Level
    message: str
    args: List[Any]
    exc_info: Tuple[Type, Exception, Any]
    task_id: Optional[int]

    @staticmethod
    def make(logger_name, level, message, args, exc_info=False):
        try:
            task_id = trio.lowlevel.current_task()
        except RuntimeError:
            # Not in trio event loop.
            task_id = None

        if task_id is not None:
            # Generates a number in range 1000-9998,
            # we won't have that many tasks, so it'll be enough for debugging purposes.
            # (using 8999 since it's a prime, so the range will be more uniformly covered)
            task_id = id(task_id) % 8999 + 1000

        return LogRecord(
            timestamp=time.time(),
            logger_name=logger_name,
            level=level,
            message=message,
            args=args,
            exc_info=sys.exc_info() if exc_info else None,
            task_id=task_id)


class Logger:

    def __init__(self, name: str = 'root', level: Level = Level.DEBUG, handlers=None, parent=None):
        self.name = name
        self.level = level
        self.handlers = handlers or []
        self.parent = parent or []

    def get_child(self, name, level=None, handlers=None):
        return Logger(
            name=self.name + '.' + name,
            level=level or self.level,
            handlers=handlers,
            parent=self)

    def _emit(self, record):
        if self.parent:
            self.parent._emit(record)

        if record.level < self.level:
            return

        for handler in self.handlers:
            handler.emit(record)

    def log(self, level, message, args, exc_info=False):
        self._emit(LogRecord.make(self.name, Level.DEBUG, message, args, exc_info=exc_info))

    def debug(self, message, *args, **kwds):
        self.log(Level.DEBUG, message, args, **kwds)

    def info(self, message, *args, **kwds):
        self.log(Level.INFO, message, args, **kwds)

    def warn(self, message, *args, **kwds):
        self.log(Level.WARNING, message, args, **kwds)

    def error(self, message, *args, **kwds):
        self.log(Level.ERROR, message, args, **kwds)

    def critical(self, message, *args, **kwds):
        self.log(Level.CRITICAL, message, args, **kwds)


NULL_LOGGER = Logger()


class Formatter:

    def __init__(self, format_str):
        self.format_str = format_str

    def format(self, record):
        message = record.message.format(*record.args)
        asctime = time.asctime(time.localtime(record.timestamp))

        full_message = self.format_str.format(
            task_id=("" if record.task_id is None else ("[" + str(record.task_id) + "] ")),
            asctime=asctime,
            name=record.logger_name,
            levelname=_LEVEL_NAMES[record.level],
            message=message)

        if record.exc_info:
            file = io.StringIO()
            traceback.print_exception(*record.exc_info, file=file)
            full_message += '\n' + file.getvalue()[:-1] # cut out the last linebreak

        return full_message


DEFAULT_FORMATTER = Formatter('{asctime} {task_id}[{levelname}] [{name}] {message}')


class ConsoleHandler:

    def __init__(self, level=Level.DEBUG, formatter=DEFAULT_FORMATTER, stderr_at=Level.WARNING):
        self.level = level
        self.formatter = formatter
        self.stderr_at = stderr_at

    def emit(self, record):
        if record.level < self.level:
            return
        message = self.formatter.format(record)
        file = sys.stderr if (self.stderr_at is not None and record.level >= self.stderr_at) else sys.stdout
        print(message, file=file)


class RotatingFileHandler:

    def __init__(self, log_file, max_bytes=1000000, backup_count=9, formatter=DEFAULT_FORMATTER, level=Level.DEBUG):
        self.level = level
        self.formatter = formatter
        self.log_file = Path(log_file).resolve()
        self.max_bytes = max_bytes
        self.backup_count = backup_count

    def _backup_file(self, idx):
        return self.log_file.with_suffix(self.log_file.suffix + '.' + str(idx))

    def _rotate(self):
        file_names = [self._backup_file(idx) for idx in reversed(range(1, self.backup_count + 1))] + [self.log_file]

        for idx, path in enumerate(file_names):
            if path.is_file():
                if idx == 0:
                    path.unlink()
                else:
                    dest_path = file_names[idx - 1]
                    path.replace(dest_path)
            elif path.exists():
                raise RuntimeError(f"A directory exists at {path}")

    def emit(self, record):
        if record.level < self.level:
            return
        message = self.formatter.format(record)
        message_bytes = message.encode()

        if self.log_file.exists() and self.log_file.stat().st_size + len(message_bytes) > self.max_bytes:
            self._rotate()

        with open(self.log_file, 'a') as f:
            print(message, file=f)
