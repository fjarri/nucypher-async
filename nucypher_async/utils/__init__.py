from contextlib import contextmanager
from pathlib import Path
import tempfile

import trio


@contextmanager
def temp_file(contents: bytes) -> Path:
    with tempfile.NamedTemporaryFile(mode="wb") as f:
        f.write(contents)
        f.flush()
        yield f.name


class BackgroundTask:

    def __init__(self, nursery, task_callable):
        self._nursery = nursery
        self._task_callable = task_callable
        self._stop_event = trio.Event()
        self._reset_event = trio.Event()
        self._next_invocation = None

    def restart_in(self, timeout):
        timeout_s = timeout.total_seconds()
        self._next_invocation = trio.current_time() + timeout_s
        self._nursery.start_soon(self._restart_in, timeout_s)

    async def _restart_in(self, timeout):

        stop = False

        async def wait_for_stop(cancel):
            nonlocal stop
            await self._stop_event.wait()
            self._stop_event = trio.Event()
            stop = True
            cancel()

        async def wait_for_reset(cancel):
            await self._reset_event.wait()
            self._reset_event = trio.Event()
            cancel()

        with trio.move_on_after(timeout):
            async with trio.open_nursery() as nursery:
                nursery.start_soon(wait_for_stop, nursery.cancel_scope.cancel)
                nursery.start_soon(wait_for_reset, nursery.cancel_scope.cancel)

        self._next_invocation = None

        if not stop:
            self._nursery.start_soon(self._task_callable, self)

    def start(self):
        self._nursery.start_soon(self._task_callable, self)

    def stop(self):
        self._stop_event.set()

    def reset(self, awaken_in):
        if self._next_invocation is not None:
            next_invocation = trio.current_time() + awaken_in.total_seconds()
            if next_invocation < self._next_invocation:
                self._next_invocation = next_invocation
                self._reset_event.set()
