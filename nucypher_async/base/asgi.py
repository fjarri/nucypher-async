from abc import ABC, abstractmethod

from ..utils.ssl import SSLCertificate, SSLPrivateKey
from ..utils.logging import Logger


class ASGIServer(ABC):

    @abstractmethod
    def host_and_port(self) -> (str, int):
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
