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
        self._shutdown_event = trio.Event()

        self._nursery.start_soon(self._task_callable, self)

    async def restart_in(self, timeout):
        with trio.move_on_after(timeout):
            await self._shutdown_event.wait()
            return
        self._nursery.start_soon(self._task_callable, self)

    def stop(self):
        self._shutdown_event.set()
