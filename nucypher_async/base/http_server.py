from abc import ABC, abstractmethod

from ..utils.ssl import SSLCertificate, SSLPrivateKey
from ..utils.logging import Logger


class HTTPServer(ABC):
    """
    An interface providing the data necessary to start up an HTTP server.
    """

    @abstractmethod
    def host_and_port(self) -> (str, int):
        # TODO: restring the host to IP addresses?
        ...

    @abstractmethod
    def ssl_certificate(self) -> SSLCertificate:
        ...

    @abstractmethod
    def ssl_private_key(self) -> SSLPrivateKey:
        ...

    @abstractmethod
    def into_asgi_app(self):
        ...

    @abstractmethod
    def logger(self) -> Logger:
        ...
