from contextlib import contextmanager
from pathlib import Path
import tempfile
from typing import Iterator, Iterable, Callable, Awaitable

import trio

from .logging import Logger


@contextmanager
def temp_file(contents: bytes) -> Iterator[Path]:
    with tempfile.NamedTemporaryFile(mode="wb") as f:
        f.write(contents)
        f.flush()
        yield Path(f.name)


async def wait_for_any(events: Iterable[trio.Event], timeout: float) -> bool:
    stop = trio.Event()

    async def wait_for_single(event: trio.Event) -> None:
        await event.wait()
        stop.set()

    try:
        with trio.fail_after(timeout):
            async with trio.open_nursery() as nursery:
                for event in events:
                    nursery.start_soon(wait_for_single, event)
                await stop.wait()
                nursery.cancel_scope.cancel()
    except trio.TooSlowError:
        return True

    # TODO: or determine which event fired and return that?
    return False


class BackgroundTask:
    def __init__(self, worker: Callable[[trio.Event], Awaitable[None]], logger: Logger):
        self._worker = worker
        self._logger = logger
        self._stop_event = trio.Event()
        self._stop_finished_event = trio.Event()

    async def _wrapper(self) -> None:
        try:
            await self._worker(self._stop_event)
        except Exception as exc:
            self._logger.error("Unhandled exception in a BackgroundTask", exc_info=True)
        finally:
            self._stop_finished_event.set()

    def start(self, nursery: trio.Nursery) -> None:
        nursery.start_soon(self._wrapper)

    async def stop(self) -> None:
        self._stop_event.set()
        await self._stop_finished_event.wait()
        self._stop_event = trio.Event()
        self._stop_finished_event = trio.Event()
