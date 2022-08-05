"""
The job of the REST dirver is to encapsulate dealing with the specific request library
(currently ``httpx``), extract request data and convert status codes to exceptions.
It is the "client" countrerpart of ``asgi_app``.
"""

from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
import http
from ipaddress import IPv4Address, AddressValueError
from typing import Tuple, AsyncIterator

import arrow
import httpx
from nucypher_core import (
    NodeMetadata, MetadataRequest, MetadataResponse, ReencryptionRequest, ReencryptionResponse,
    NodeMetadataPayload)
import trio

from ..base.http_server import BaseHTTPServer
from ..base.peer import PeerError, BasePeer, decode_peer_error
from ..base.time import BaseClock
from ..utils import temp_file
from ..utils.ssl import SSLCertificate, SSLPrivateKey, fetch_certificate
from .asgi_app import make_peer_asgi_app


class InvalidErrorFormat(PeerError):
    pass


class ConnectionError(PeerError):
    pass


class HandshakeError(PeerError):
    pass


class PeerVerificationError(PeerError):
    pass


class Contact:

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    @classmethod
    def from_metadata(cls, metadata: NodeMetadata) -> "Contact":
        return cls(metadata.payload.host, metadata.payload.port)

    def __eq__(self, other):
        return self.host == other.host and self.port == other.port

    def __hash__(self):
        return hash((self.__class__, self.host, self.port))

    def __repr__(self):
        return f"Contact({repr(self.host)}, {repr(self.port)})"


class PeerPrivateKey:

    def __init__(self, seed: bytes):
        self.__seed = seed

    def as_ssl_private_key(self) -> SSLPrivateKey:
        return SSLPrivateKey.from_seed(self.__seed)


class PeerPublicKey:

    def __init__(self, certificate: SSLCertificate):
        self._certificate = certificate

    def __bytes__(self):
        return self._certificate.to_der_bytes()


class SecureContact:

    @classmethod
    def checked(cls, contact: Contact, public_key: PeerPublicKey) -> "SecureContact":
        certificate = public_key._certificate
        try:
            certificate.verify()
        except SSLCertificate.InvalidSignature as exc:
            raise HandshakeError(f"Invalid certificate signature") from exc

        if certificate.declared_host != contact.host:
            raise HandshakeError(
                f"Host mismatch: contact has {contact.host}, "
                f"but certificate has {certificate.declared_host}")

        return cls(contact, certificate)

    @classmethod
    def generate(cls, private_key: PeerPrivateKey, clock: BaseClock, contact: Contact):
        certificate = SSLCertificate.self_signed(clock.utcnow(), private_key.as_ssl_private_key(), contact.host)
        return cls(contact, certificate)

    def __init__(self, contact: Contact, certificate: SSLCertificate):
        self.contact = contact
        self.public_key = PeerPublicKey(certificate)

        self.not_valid_before = arrow.get(certificate.not_valid_before)
        self.not_valid_after = arrow.get(certificate.not_valid_after)

    def __eq__(self, other):
        return self.contact == other.contact and self.public_key == other.public_key

    @property
    def uri(self) -> str:
        return f"https://{self.contact.host}:{self.contact.port}"


class PeerInfo:

    @staticmethod
    def _get_certificate(payload: NodeMetadataPayload) -> SSLCertificate:
        try:
            return SSLCertificate.from_der_bytes(payload.certificate_der)
        except Exception as e:
            raise PeerVerificationError(f"Invalid certificate bytes in the payload: {e}") from e

    @classmethod
    def _checked(cls, metadata: NodeMetadata, payload: NodeMetadataPayload, clock: BaseClock, reference_contact: SecureContact) -> "PeerInfo":

        payload_contact = Contact(payload.host, payload.port)
        if reference_contact.contact != payload_contact:
            raise PeerVerificationError(
                f"Contact info mismatch: expected {reference_contact.contact}, "
                f"{payload_contact} in the metadata")

        now = clock.utcnow()
        if reference_contact.not_valid_before > now:
            raise PeerVerificationError(
                f"Peer contact is only valid after {reference_contact.not_valid_before}")
        if reference_contact.not_valid_after < now:
            raise PeerVerificationError(
                f"Peer contact is only valid until {reference_contact.not_valid_after}")

        return cls(metadata=metadata, secure_contact=reference_contact)

    @classmethod
    def checked_remote(cls, metadata: NodeMetadata, clock: BaseClock, received_from: SecureContact) -> "PeerInfo":

        payload = metadata.payload
        certificate = cls._get_certificate(payload)

        if payload.certificate_der != received_from.public_key._certificate.to_der_bytes():
            raise PeerVerificationError(f"Certificate mismatch between the payload and the contact")

        return cls._checked(metadata, payload, clock, received_from)

    @classmethod
    def checked_local(cls, metadata: NodeMetadata, clock: BaseClock, private_key: PeerPrivateKey, contact: Contact) -> "PeerInfo":

        payload = metadata.payload
        certificate = cls._get_certificate(payload)

        metadata_contact = Contact(payload.host, payload.port)
        if metadata_contact != contact:
            raise PeerVerificationError(
                f"Contact mismatch: expected {contact}, {metadata_contact} in the metadata")

        expected_public_key = private_key.as_ssl_private_key().public_key()
        if certificate.public_key() != expected_public_key:
            raise PeerVerificationError(
                f"Certificate public key mismatch: expected {expected_public_key},"
                f"{certificate.public_key()} in the certificate")

        secure_contact = SecureContact.checked(contact, PeerPublicKey(certificate))

        return cls._checked(metadata, payload, clock, secure_contact)

    def __init__(self, metadata: NodeMetadata, secure_contact: SecureContact):
        self.metadata = metadata
        self.secure_contact = secure_contact


def unwrap_bytes(response, cls):
    if response.status_code != http.HTTPStatus.OK:
        peer_exc: PeerError = decode_peer_error(response.text)
        raise peer_exc
    message_bytes = response.read()
    try:
        message = cls.from_bytes(message_bytes)
    except ValueError as exc:
        # Should we have a different error type for message format errors on client side?
        raise InvalidMessage.for_message(cls, exc) from exc
    return message


class PeerClient:

    @asynccontextmanager
    async def _http_client(self, certificate: SSLCertificate) -> AsyncIterator[httpx.AsyncClient]:
        # It would be nice avoid saving the certificate to disk at each request.
        # Having a cache directory requires too much architectural overhead,
        # and with the current frequency of REST calls it just isn't worth it.
        # Maybe the long-standing https://bugs.python.org/issue16487 will finally get fixed,
        # and we will be able to load certificates from memory.
        with temp_file(certificate.to_pem_bytes()) as filename:
            # Timeouts are caught at top level, as per `trio` style.
            async with httpx.AsyncClient(verify=str(filename), timeout=None) as client:
                try:
                    yield client
                except httpx.HTTPError as e:
                    raise ConnectionError(str(e)) from e
                except OSError as e:
                    raise ConnectionError(str(e)) from e

    async def _fetch_certificate(self, contact: Contact) -> SSLCertificate:
        try:
            return await fetch_certificate(contact.host, contact.port)
        except OSError as e:
            raise ConnectionError(str(e)) from e

    async def handshake(self, contact: Contact) -> SecureContact:
        certificate = await self._fetch_certificate(contact)
        return SecureContact.checked(contact, PeerPublicKey(certificate))

    async def ping(self, secure_contact: SecureContact) -> str:
        async with self._http_client(secure_contact.public_key._certificate) as client:
            response = await client.get(secure_contact.uri + '/ping')
        return response.text

    async def node_metadata_get(self, secure_contact: SecureContact) -> MetadataResponse:
        async with self._http_client(secure_contact.public_key._certificate) as client:
            response = await client.get(secure_contact.uri + '/node_metadata')
        return unwrap_bytes(response, MetadataResponse)

    async def node_metadata_post(self, secure_contact: SecureContact, metadata_request: MetadataRequest) -> MetadataResponse:
        async with self._http_client(secure_contact.public_key._certificate) as client:
            response = await client.post(secure_contact.uri + '/node_metadata', content=bytes(metadata_request))
        return unwrap_bytes(response, MetadataResponse)

    async def public_information(self, secure_contact: SecureContact, clock: BaseClock) -> PeerInfo:
        async with self._http_client(secure_contact.public_key._certificate) as client:
            response = await client.get(secure_contact.uri + '/public_information')
        metadata = unwrap_bytes(response, NodeMetadata)
        return PeerInfo.checked_remote(metadata, clock, secure_contact)

    async def reencrypt(self, secure_contact: SecureContact, reencryption_request: ReencryptionRequest) -> ReencryptionResponse:
        async with self._http_client(secure_contact.public_key._certificate) as client:
            response = await client.post(secure_contact.uri + '/reencrypt', content=bytes(reencryption_request))
        return unwrap_bytes(response, ReencryptionResponse)


class BasePeerServer(ABC):

    @abstractmethod
    def secure_contact(self) -> SecureContact:
        ...

    @abstractmethod
    def peer_private_key(self) -> PeerPrivateKey:
        ...

    @abstractmethod
    def peer(self) -> BasePeer:
        ...


class PeerHTTPServer(BaseHTTPServer):
    """
    An adapter from peer server to HTTP server.
    """

    def __init__(self, server: BasePeerServer):
        self.server = server

    def host_and_port(self) -> Tuple[str, int]:
        contact = self.server.secure_contact().contact
        return contact.host, contact.port

    def ssl_certificate(self) -> SSLCertificate:
        return self.server.secure_contact().public_key._certificate

    def ssl_private_key(self) -> SSLPrivateKey:
        return self.server.peer_private_key().as_ssl_private_key()

    def into_asgi_app(self):
        return make_peer_asgi_app(self.server.peer())
