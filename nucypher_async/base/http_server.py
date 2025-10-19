from abc import ABC, abstractmethod

from hypercorn.typing import ASGIFramework

from ..utils.ssl import SSLCertificate, SSLPrivateKey


class BaseHTTPServer(ABC):
    """An interface providing the data necessary to start up an HTTP server."""

    @abstractmethod
    def host_and_port(self) -> tuple[str, int]:
        # TODO: restrict the host to IP addresses?
        ...

    @abstractmethod
    def ssl_certificate(self) -> SSLCertificate: ...

    @abstractmethod
    def ssl_ca_chain(self) -> list[SSLCertificate] | None: ...

    @abstractmethod
    def ssl_private_key(self) -> SSLPrivateKey: ...

    @abstractmethod
    def into_asgi_app(self) -> ASGIFramework: ...
