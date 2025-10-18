import tempfile
from collections.abc import Awaitable, Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

import trio

from .logging import Logger


@contextmanager
def temp_file(contents: bytes) -> Iterator[Path]:
    with tempfile.NamedTemporaryFile(mode="wb") as file:
        file.write(contents)
        file.flush()
        yield Path(file.name)


async def wait_for_any(events: Iterable[trio.Event]) -> trio.Event | None:
    stop = trio.Event()
    fired_event = None

    async def wait_for_single(event: trio.Event) -> None:
        await event.wait()

        nonlocal fired_event
        fired_event = event

        stop.set()

    async with trio.open_nursery() as nursery:
        for event in events:
            nursery.start_soon(wait_for_single, event)
        await stop.wait()
        nursery.cancel_scope.cancel()

    return fired_event


class BackgroundTask:
    def __init__(self, worker: Callable[[trio.Event], Awaitable[None]], logger: Logger):
        self._worker = worker
        self._logger = logger
        self._stop_event = trio.Event()
        self._stop_finished_event = trio.Event()

    async def _wrapper(self) -> None:
        try:
            await self._worker(self._stop_event)
        except Exception:
            self._logger.error("Unhandled exception in a BackgroundTask", exc_info=True)
            raise
        finally:
            self._stop_finished_event.set()

    def start(self, nursery: trio.Nursery) -> None:
        nursery.start_soon(self._wrapper)

    async def stop(self) -> None:
        self._stop_event.set()
        await self._stop_finished_event.wait()
        self._stop_event = trio.Event()
        self._stop_finished_event = trio.Event()
