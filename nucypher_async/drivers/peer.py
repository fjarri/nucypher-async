"""
The job of the REST dirver is to encapsulate dealing with the specific request library
(currently ``httpx``), extract request data and convert status codes to exceptions.
It is the "client" countrerpart of ``asgi_app``.
"""

from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from functools import cached_property
import http
from typing import Tuple, AsyncIterator, Any, Optional

import arrow
import httpx

from ..base.http_server import BaseHTTPServer, ASGIFramework
from ..base.peer import PeerError, decode_peer_error
from ..base.ursula import BaseUrsulaServer
from ..base.time import BaseClock
from ..utils import temp_file
from ..utils.ssl import SSLCertificate, SSLPrivateKey, fetch_certificate
from .asgi_app import make_ursula_asgi_app


class PeerConnectionError(PeerError):
    pass


class HandshakeError(PeerError):
    pass


class Contact:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def uri(self) -> str:
        return f"https://{self.host}:{self.port}"

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Contact) and self.host == other.host and self.port == other.port

    def __hash__(self) -> int:
        return hash((self.__class__, self.host, self.port))

    def __repr__(self) -> str:
        return f"Contact({repr(self.host)}, {repr(self.port)})"


class PeerPrivateKey:
    @classmethod
    def from_seed(cls, seed: bytes) -> "PeerPrivateKey":
        return cls(SSLPrivateKey.from_seed(seed))

    def __init__(self, private_key: SSLPrivateKey):
        self.__private_key = private_key

    def _as_ssl_private_key(self) -> SSLPrivateKey:
        return self.__private_key

    def matches(self, public_key: "PeerPublicKey") -> bool:
        expected_public_key = self._as_ssl_private_key().public_key()
        certificate = public_key._as_ssl_certificate()
        return certificate.public_key() == expected_public_key


class PeerPublicKey:
    @classmethod
    def generate(
        cls, private_key: PeerPrivateKey, clock: BaseClock, contact: Contact
    ) -> "PeerPublicKey":
        certificate = SSLCertificate.self_signed(
            clock.utcnow(), private_key._as_ssl_private_key(), contact.host
        )
        return cls(certificate)

    def __init__(self, certificate: SSLCertificate):
        # Not checking the certificate signature at this level.
        # For all we care it's just a public key, and if it is signed by the blockchain address,
        # and the other side has the corresponding private key, that's enough.
        # The HTTP client can do additional verification (possibly following the CA chain).
        self._certificate = certificate
        self.declared_host = self._certificate.declared_host

    @cached_property
    def not_valid_before(self) -> arrow.Arrow:
        return arrow.get(self._certificate.not_valid_before)

    @cached_property
    def not_valid_after(self) -> arrow.Arrow:
        return arrow.get(self._certificate.not_valid_after)

    def _as_ssl_certificate(self) -> SSLCertificate:
        return self._certificate

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, PeerPublicKey) and self._certificate == other._certificate

    def __bytes__(self) -> bytes:
        return self._certificate.to_der_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "PeerPublicKey":
        return cls(SSLCertificate.from_der_bytes(data))


class SecureContact:
    def __init__(self, contact: Contact, public_key: PeerPublicKey):
        # It is a slight abstraction leak, but since we do use the hostname
        # when creating a public key, it is logical to also check that it is correct,
        # and this is the best place to do it.
        if public_key.declared_host != contact.host:
            raise HandshakeError(
                f"Host mismatch: contact has {contact.host}, "
                f"but certificate has {public_key.declared_host}"
            )

        self.contact = contact
        self.public_key = public_key

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, SecureContact)
            and self.contact == other.contact
            and self.public_key == other.public_key
        )

    @property
    def _uri(self) -> str:
        return self.contact.uri()


class PeerClient:
    @asynccontextmanager
    async def _http_client(self, public_key: PeerPublicKey) -> AsyncIterator[httpx.AsyncClient]:
        """
        Creates a client context manager to send HTTP requests.
        Can be overridden in mocks.
        """

        # It would be nice avoid saving the certificate to disk at each request.
        # Having a cache directory requires too much architectural overhead,
        # and with the current frequency of REST calls it just isn't worth it.
        # Maybe the long-standing https://bugs.python.org/issue16487 will finally get fixed,
        # and we will be able to load certificates from memory.
        with temp_file(public_key._as_ssl_certificate().to_pem_bytes()) as filename:
            # Timeouts are caught at top level, as per `trio` style.
            async with httpx.AsyncClient(verify=str(filename), timeout=None) as client:
                try:
                    yield client
                except httpx.HTTPError as exc:
                    raise PeerConnectionError(str(exc)) from exc
                except OSError as exc:
                    raise PeerConnectionError(str(exc)) from exc

    async def _fetch_certificate(self, contact: Contact) -> SSLCertificate:
        """
        Fetches the SSL certificate for the contact.
        Can be overridden in mocks.
        """
        try:
            return await fetch_certificate(contact.host, contact.port)
        except OSError as exc:
            raise PeerConnectionError(str(exc)) from exc

    async def handshake(self, contact: Contact) -> SecureContact:
        """
        Resolves a peer contact into a secure contact that can be used for communication.
        """
        certificate = await self._fetch_certificate(contact)
        public_key = PeerPublicKey(certificate)
        return SecureContact(contact, public_key)

    async def communicate(
        self, secure_contact: SecureContact, route: str, data: Optional[bytes] = None
    ) -> bytes:
        """
        Sends an optional message to the specified route and returns the response bytes.
        """
        async with self._http_client(secure_contact.public_key) as client:
            path = secure_contact._uri + "/" + route
            if data is None:
                response = await client.get(path)
            else:
                response = await client.post(path, content=data)

            response_data = response.read()
            if response.status_code != http.HTTPStatus.OK:
                raise decode_peer_error(response_data)
            return response_data


class BasePeerServer(ABC):
    @abstractmethod
    def secure_contact(self) -> SecureContact:
        ...

    @abstractmethod
    def peer_private_key(self) -> PeerPrivateKey:
        ...


class BasePeerAndUrsulaServer(BasePeerServer, BaseUrsulaServer):
    ...


class UrsulaHTTPServer(BaseHTTPServer):
    """
    An adapter from peer server to HTTP server.
    """

    def __init__(self, server: BasePeerAndUrsulaServer):
        self.server = server

    def host_and_port(self) -> Tuple[str, int]:
        contact = self.server.secure_contact().contact
        return contact.host, contact.port

    def ssl_certificate(self) -> SSLCertificate:
        return self.server.secure_contact().public_key._as_ssl_certificate()

    def ssl_private_key(self) -> SSLPrivateKey:
        return self.server.peer_private_key()._as_ssl_private_key()

    def into_asgi_app(self) -> ASGIFramework:
        return make_ursula_asgi_app(self.server)
