"""
The job of the peer dirver is to encapsulate dealing with the specific way peers communicate
(currently, this is HTTP requests), along with the library used for this purpose (`httpx`).
The related details are also hidden here (e.g. that a peer contact is a DNS name + port,
or that its transport key is a SSL certificate).
"""

import http
import ssl
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from functools import cached_property
from ipaddress import ip_address

import arrow
import httpx
import trio

from ..base.time import BaseClock
from ..utils import temp_file
from ..utils.ssl import SSLCertificate, SSLPrivateKey, fetch_certificate
from .errors import PeerError


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

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Contact) and self.host == other.host and self.port == other.port

    def __hash__(self) -> int:
        return hash((self.__class__, self.host, self.port))

    def __repr__(self) -> str:
        return f"Contact({self.host!r}, {self.port!r})"


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
        certificate = public_key._as_ssl_certificate()  # noqa: SLF001
        return certificate.public_key() == expected_public_key


class PeerPublicKey:
    @classmethod
    def generate(
        cls, private_key: PeerPrivateKey, clock: BaseClock, contact: Contact
    ) -> "PeerPublicKey":
        certificate = SSLCertificate.self_signed(
            clock.utcnow(),
            private_key._as_ssl_private_key(),  # noqa: SLF001
            contact.host,
        )
        return cls(certificate)

    def __init__(
        self, certificate: SSLCertificate, ca_chain: Iterable[SSLCertificate] | None = None
    ):
        # Not checking the certificate signature at this level.
        # For all we care it's just a public key.
        # The HTTP client can do additional verification (possibly following the CA chain).
        self._certificate = certificate
        # TODO: check that the chain is valid?
        self._ca_chain = list(ca_chain) if ca_chain else []
        self.declared_host = self._certificate.declared_host

    @cached_property
    def not_valid_before(self) -> arrow.Arrow:
        return arrow.get(self._certificate.not_valid_before)

    @cached_property
    def not_valid_after(self) -> arrow.Arrow:
        return arrow.get(self._certificate.not_valid_after)

    def _as_ssl_certificate(self) -> SSLCertificate:
        return self._certificate

    def _as_ssl_ca_chain(self) -> list[SSLCertificate]:
        return self._ca_chain

    def __eq__(self, other: object) -> bool:
        # TODO: should we compare the chains too?
        # Is it possible to have two equal certificates and valid but different chains?
        return isinstance(other, PeerPublicKey) and self._certificate == other._certificate

    def __hash__(self) -> int:
        return hash((type(self), self._certificate))

    def __bytes__(self) -> bytes:
        return self._certificate.to_der_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "PeerPublicKey":
        return cls(SSLCertificate.from_der_bytes(data))


async def get_alternative_contact(contact: Contact) -> Contact | None:
    """Returns an alternative contact, if one exists."""
    # TODO: this is a temporary workaround for seed nodes whose contacts have domain names,
    # but certificates are issued for IPs.

    try:
        ip_address(contact.host)
    except ValueError:
        pass
    else:
        # The host is already an IP address, nothing to do.
        return None

    try:
        # Note that with some providers it can give some kind of a default IP
        # for any hostname that doesn't actually exist.
        # Doesn't seem like we can do much about it.
        addrinfo = await trio.socket.getaddrinfo(contact.host, contact.port)
    except trio.socket.gaierror:
        return None

    # TODO: or should we select a specific entry?
    _family, _type, _proto, _canonname, sockaddr = addrinfo[0]
    # Can have 2 additional components for IPv6, but we're not interested in those.
    ip_addr, port, *_ = sockaddr

    # Sanity check. When would it not be the case?
    assert isinstance(ip_addr, str)
    assert isinstance(port, int)
    assert port == contact.port

    return Contact(ip_addr, port)


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

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, SecureContact)
            and self.contact == other.contact
            and self.public_key == other.public_key
        )

    def __hash__(self) -> int:
        return hash((type(self), self.contact, self.public_key))

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
        with temp_file(public_key._as_ssl_certificate().to_pem_bytes()) as filename:  # noqa: SLF001
            # Timeouts are caught at top level, as per `trio` style.
            context = ssl.create_default_context(cafile=str(filename))
            async with httpx.AsyncClient(verify=context, timeout=None) as client:  # noqa: S113
                try:
                    yield client
                except (OSError, httpx.HTTPError) as exc:
                    exc_message = str(exc)
                    message = str(type(exc)) + (f" {exc_message}" if exc_message else "")
                    raise PeerConnectionError(message) from exc

    async def _fetch_certificate(self, contact: Contact) -> SSLCertificate:
        """
        Fetches the SSL certificate for the contact.
        Can be overridden in mocks.
        """
        try:
            return await fetch_certificate(contact.host, contact.port)
        except RuntimeError as exc:
            raise PeerConnectionError(str(exc)) from exc

    async def handshake(self, contact: Contact) -> SecureContact:
        """Resolves a peer contact into a secure contact that can be used for communication."""
        certificate = await self._fetch_certificate(contact)
        public_key = PeerPublicKey(certificate)
        return SecureContact(contact, public_key)

    async def communicate(
        self, secure_contact: SecureContact, route: str, data: bytes | None = None
    ) -> bytes:
        """Sends an optional message to the specified route and returns the response bytes."""
        async with self._http_client(secure_contact.public_key) as client:
            path = f"{secure_contact._uri}/{route}"  # noqa: SLF001
            if data is None:
                response = await client.get(path)
            else:
                response = await client.post(path, content=data)

            response_data = response.read()
            if response.status_code != http.HTTPStatus.OK:
                raise PeerError.from_json(response_data)
            return response_data
