import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from ._concurrency import BackgroundTask, wait_for_any
from ._producer import producer

__all__ = ["BackgroundTask", "producer", "wait_for_any"]


@contextmanager
def temp_file(contents: bytes) -> Iterator[Path]:
    with tempfile.NamedTemporaryFile(mode="wb") as file:
        file.write(contents)
        file.flush()
        yield Path(file.name)
