from contextlib import contextmanager
from pathlib import Path
import tempfile

import trio

from .certificate import SSLCertificate


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


class Contact:

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    @property
    def url(self):
        return f"https://{host}:{port}"

    def __eq__(self, other):
        return self.host == other.host and self.port == other.port

    def __hash__(self):
        return hash((self.__class__, self.host, self.port))

    def __repr__(self):
        return f"Contact({repr(self.host)}, {repr(self.port)})"


class SSLContact:

    def __init__(self, contact: Contact, certificate: SSLCertificate):
        assert certificate.declared_host == contact.host

        self.contact = contact
        self.certificate = certificate

    def __eq__(self, other):
        return self.contact == other.contact and self.certificate == other.certificate
