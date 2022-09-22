"""
This could be a separate library, but we're keeping it a submodule for now
for the ease of development.

Why not use standard library `logging`: it is stateful, and we want different behavior
depening on the environment (testing/usage as a library/running a server).
"""

from abc import ABC, abstractmethod
from enum import IntEnum
import io
import time
import traceback
from typing import Any, Tuple, Optional, Type, Union, Iterable
from types import TracebackType
from pathlib import Path
import sys

from attr import frozen
import trio


class Level(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


_LEVEL_NAMES = {
    Level.DEBUG: "debug",
    Level.INFO: "info",
    Level.WARNING: "warning",
    Level.ERROR: "error",
    Level.CRITICAL: "critical",
}


DEBUG = Level.DEBUG
INFO = Level.INFO
WARNING = Level.WARNING
ERROR = Level.ERROR
CRITICAL = Level.CRITICAL


@frozen
class LogRecord:
    timestamp: float
    logger_name: str
    level: Level
    message: str
    args: Tuple[Any, ...]
    exc_info: Union[
        Tuple[Type[BaseException], BaseException, TracebackType], Tuple[None, None, None]
    ]
    task_id: Optional[int]

    @staticmethod
    def make(
        logger_name: str, level: Level, message: str, args: Tuple[Any, ...], exc_info: bool = False
    ) -> "LogRecord":
        try:
            task = trio.lowlevel.current_task()
        except RuntimeError:
            # Not in trio event loop.
            task = None

        if task is not None:
            # Generates a number in range 1000-9998,
            # we won't have that many tasks, so it'll be enough for debugging purposes.
            # (using 8999 since it's a prime, so the range will be more uniformly covered)
            task_id = id(task) % 8999 + 1000
        else:
            task_id = None

        return LogRecord(
            timestamp=time.time(),  # Note: using the local time here, not UTC
            logger_name=logger_name,
            level=level,
            message=message,
            args=args,
            exc_info=sys.exc_info() if exc_info else (None, None, None),
            task_id=task_id,
        )


class Formatter(ABC):
    @abstractmethod
    def format(self, record: LogRecord) -> str:
        ...


class Handler(ABC):
    @abstractmethod
    def emit(self, record: LogRecord) -> None:
        ...


class Logger:
    def __init__(
        self,
        name: str = "root",
        level: Level = Level.DEBUG,
        handlers: Optional[Iterable[Handler]] = None,
        parent: Optional["Logger"] = None,
    ):
        self.name = name
        self.level = level
        self.handlers = handlers or []
        self.parent = parent

    def get_child(
        self, name: str, level: Optional[Level] = None, handlers: Optional[Iterable[Handler]] = None
    ) -> "Logger":
        return Logger(
            name=self.name + "." + name,
            level=level or self.level,
            handlers=handlers,
            parent=self,
        )

    def _emit(self, record: LogRecord) -> None:
        if self.parent:
            self.parent._emit(record)

        if record.level < self.level:
            return

        for handler in self.handlers:
            handler.emit(record)

    def _log(
        self, level: Level, message: str, args: Tuple[Any, ...], exc_info: bool = False
    ) -> None:
        self._emit(LogRecord.make(self.name, level, message, args, exc_info=exc_info))

    def debug(self, message: str, *args: Any, **kwds: Any) -> None:
        self._log(Level.DEBUG, message, args, **kwds)

    def info(self, message: str, *args: Any, **kwds: Any) -> None:
        self._log(Level.INFO, message, args, **kwds)

    def warn(self, message: str, *args: Any, **kwds: Any) -> None:
        self._log(Level.WARNING, message, args, **kwds)

    def error(self, message: str, *args: Any, **kwds: Any) -> None:
        self._log(Level.ERROR, message, args, **kwds)

    def critical(self, message: str, *args: Any, **kwds: Any) -> None:
        self._log(Level.CRITICAL, message, args, **kwds)


NULL_LOGGER = Logger()


class DefaultFormatter(Formatter):
    def __init__(self, format_str: str):
        self.format_str = format_str

    def format(self, record: LogRecord) -> str:
        message = record.message.format(*record.args)
        asctime = time.asctime(time.localtime(record.timestamp))

        full_message = self.format_str.format(
            task_id=("" if record.task_id is None else ("[" + str(record.task_id) + "] ")),
            asctime=asctime,
            name=record.logger_name,
            levelname=_LEVEL_NAMES[record.level],
            message=message,
        )

        if record.exc_info != (None, None, None):
            file = io.StringIO()
            exc_type, value, tback = record.exc_info
            traceback.print_exception(exc_type, value=value, tb=tback, file=file)
            full_message += "\n" + file.getvalue()[:-1]  # cut out the last linebreak

        return full_message


DEFAULT_FORMATTER = DefaultFormatter("{asctime} {task_id}[{levelname}] [{name}] {message}")


class ConsoleHandler(Handler):
    def __init__(
        self,
        level: Level = Level.DEBUG,
        formatter: Formatter = DEFAULT_FORMATTER,
        stderr_at: Optional[Level] = Level.WARNING,
    ):
        self.level = level
        self.formatter = formatter
        self.stderr_at = stderr_at

    def emit(self, record: LogRecord) -> None:
        if record.level < self.level:
            return
        message = self.formatter.format(record)
        file = (
            sys.stderr
            if (self.stderr_at is not None and record.level >= self.stderr_at)
            else sys.stdout
        )
        print(message, file=file)


class RotatingFileHandler(Handler):
    def __init__(
        self,
        log_file: Union[Path, str],
        max_bytes: int = 1000000,
        backup_count: int = 9,
        formatter: Formatter = DEFAULT_FORMATTER,
        level: Level = Level.DEBUG,
    ):
        self.level = level
        self.formatter = formatter
        self.log_file = Path(log_file).resolve()
        self.log_dir = self.log_file.parent
        self.max_bytes = max_bytes
        self.backup_count = backup_count

    def _backup_file(self, idx: int) -> Path:
        return self.log_file.with_suffix(self.log_file.suffix + "." + str(idx))

    def _rotate(self) -> None:
        file_names = [
            self._backup_file(idx) for idx in reversed(range(1, self.backup_count + 1))
        ] + [self.log_file]

        for idx, path in enumerate(file_names):
            if path.is_file():
                if idx == 0:
                    path.unlink()
                else:
                    dest_path = file_names[idx - 1]
                    path.replace(dest_path)
            elif path.exists():
                raise RuntimeError(f"A directory exists at {path}")

    def emit(self, record: LogRecord) -> None:
        if record.level < self.level:
            return
        message = self.formatter.format(record)
        message_bytes = message.encode()

        self.log_dir.mkdir(parents=True, exist_ok=True)

        if (
            self.log_file.exists()
            and self.log_file.stat().st_size + len(message_bytes) > self.max_bytes
        ):
            self._rotate()

        with open(self.log_file, "a", encoding="utf-8") as file:
            print(message, file=file)
