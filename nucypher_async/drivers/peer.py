"""
The job of the REST dirver is to encapsulate dealing with the specific request library
(currently ``httpx``), extract request data and convert status codes to exceptions.
It is the "client" countrerpart of ``rest_app``.
"""

from contextlib import asynccontextmanager
import http
from ipaddress import IPv4Address, AddressValueError

import arrow
import httpx
from nucypher_core import (
    NodeMetadata, MetadataRequest, MetadataResponse, ReencryptionRequest, ReencryptionResponse)

from .ssl import SSLCertificate, SSLPrivateKey, fetch_certificate
from ..utils import temp_file


class P2PNetworkError(Exception):
    pass


class RPCError(P2PNetworkError):

    def __init__(self, message, http_status_code):
        super().__init__(message)
        self.http_status_code = http_status_code


class MessageFormatError(RPCError):
    http_status_code = http.HTTPStatus.INTERNAL_SERVER_ERROR

    @classmethod
    def for_message(cls, message_cls, exc):
        cls(f"Failed to parse {message_cls.__name__} bytes: {exc}")


class InactivePolicy(RPCError):
    http_status_code = http.HTTPStatus.PAYMENT_REQUIRED


class ConnectionError(P2PNetworkError):
    pass


class HandshakeError(P2PNetworkError):
    pass


class Contact:

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    @classmethod
    def from_metadata(cls, metadata: NodeMetadata):
        return cls(metadata.payload.host, metadata.payload.port)

    def __eq__(self, other):
        return self.host == other.host and self.port == other.port

    def __hash__(self):
        return hash((self.__class__, self.host, self.port))

    def __repr__(self):
        return f"Contact({repr(self.host)}, {repr(self.port)})"


class SecureContactError(Exception):
    pass


class SecureContact:

    @classmethod
    def checked(cls, contact: Contact, certificate: SSLCertificate):

        try:
            certificate.verify()
        except ssl.InvalidSignature as exc:
            raise SecureContactError(f"Invalid certificate signature") from exc

        if certificate.declared_host != contact.host:
            raise SecureContactError(
                f"Host mismatch: contact has {contact.host}, "
                f"but certificate has {certificate.declared_host}")

        return cls(contact, certificate)

    @classmethod
    def generate(cls, private_key, clock, contact):
        certificate = SSLCertificate.self_signed(clock, private_key.as_ssl_private_key(), contact.host)
        return cls(contact, certificate)

    def __init__(self, contact: Contact, certificate: SSLCertificate):
        self.contact = contact
        self.public_key = PeerPublicKey(certificate)

        self.not_valid_before = arrow.get(certificate.not_valid_before)
        self.not_valid_after = arrow.get(certificate.not_valid_after)

    def __eq__(self, other):
        return self.contact == other.contact and self.certificate == other.certificate

    @property
    def uri(self):
        return f"https://{self.contact.host}:{self.contact.port}"


def unwrap_bytes(response, cls):
    if response.status_code != http.HTTPStatus.OK:
        raise RPCError.from_status_code(response.text, response.status_code)
    message_bytes = response.read()
    try:
        message = cls.from_bytes(message_bytes)
    except ValueError as exc:
        raise MessageFormatError.for_message(cls, exc) from exc
    return message


class PeerClient:

    @asynccontextmanager
    async def _http_client(self, certificate: SSLCertificate):
        # It would be nice avoid saving the certificate to disk at each request.
        # Having a cache directory requires too much architectural overhead,
        # and with the current frequency of REST calls it just isn't worth it.
        # Maybe the long-standing https://bugs.python.org/issue16487 will finally get fixed,
        # and we will be able to load certificates from memory.
        with temp_file(certificate.to_pem_bytes()) as filename:
            # Timeouts are caught at top level, as per `trio` style.
            async with httpx.AsyncClient(verify=filename, timeout=None) as client:
                try:
                    yield client
                except httpx.HTTPError as e:
                    raise ConnectionError(str(e)) from e
                except OSError as e:
                    raise ConnectionError(str(e)) from e

    async def _fetch_certificate(self, contact: Contact):
        try:
            return await fetch_certificate(contact.host, contact.port)
        except OSError as e:
            raise ConnectionError(str(e)) from e

    async def _resolve_address(self, contact: Contact):
        # TODO: what does it raise? Intercept and re-raise ConnectionError
        addrinfo = await trio.socket.getaddrinfo(contact.host, contact.port)

        # TODO: or should we select a specific entry?
        family, type_, proto, canonname, sockaddr = addrinfo[0]
        ip_addr, port = sockaddr

        # Sanity check. When would it not be the case?
        assert port == contact.port

        return Contact(ip_addr, port)

    async def handshake(self, contact: Contact) -> SecureContact:
        # TODO: wrap anything that can happen here in a HandshakeError
        try:
            addr = IPv4Address(contact.host)
        except AddressValueError:
            # If host is not an IP address, resolve it to an IP.
            # Nucypher nodes have their IPs included in the certificates,
            # so we will need it to check that the certificate is made for the right address.
            resolved_contact = await self._resolve_address(contact)
        else:
            resolved_contact = contact

        certificate = await self._fetch_certificate(contact)

        try:
            return SecureContact.checked(resolved_contact, certificate)
        except SecureContactError as exc:
            raise HandshakeError(str(exc)) from exc

    async def ping(self, secure_contact: SecureContact) -> str:
        async with self._http_client(secure_contact.public_key._certificate) as client:
            response = await client.get(secure_contact.uri + '/ping')
        return response.text

    async def node_metadata_post(self, secure_contact: SecureContact, metadata_request: MetadataRequest):
        async with self._http_client(secure_contact.public_key._certificate) as client:
            response = await client.post(secure_contact.uri + '/node_metadata', data=bytes(metadata_request))
        return unwrap_bytes(response, MetadataResponse)

    async def public_information(self, secure_contact: SecureContact, clock):
        async with self._http_client(secure_contact.public_key._certificate) as client:
            response = await client.get(secure_contact.uri + '/public_information')
        metadata = unwrap_bytes(response, NodeMetadata)
        return Peer.checked_remote(metadata, clock, secure_contact)

    async def reencrypt(self, secure_contact: SecureContact, reencryption_request: ReencryptionRequest):
        async with self._http_client(secure_contact.public_key._certificate) as client:
            response = await client.post(secure_contact.uri + '/reencrypt', data=bytes(reencryption_request))
        return unwrap_bytes(response, ReencryptionResponse)


class PeerVerificationError(Exception):
    pass


class Peer:

    @staticmethod
    def _get_certificate(payload):
        try:
            certificate = SSLCertificate.from_der_bytes(payload.certificate_der)
        except Exception as e:
            raise PeerVerificationError(f"Invalid certificate bytes in the payload: {e}") from e

    @classmethod
    def _checked(cls, metadata, payload, clock, reference_contact):

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
    def checked_remote(cls, metadata: NodeMetadata, clock, received_from: SecureContact):

        payload = metadata.payload
        certificate = cls._get_certificate(payload)

        if payload.certificate_der != received_from.public_key._certificate.to_der_bytes():
            raise PeerVerificationError(f"Certificate mismatch between the payload and the contact")

        return cls._checked(metadata, payload, clock, received_from)

    @classmethod
    def checked_local(cls, metadata: NodeMetadata, clock, private_key, contact):

        payload = metadata.payload
        certificate = cls._get_certificate(payload)

        expected_public_key = private_key.as_ssl_private_key().public_key()
        if certificate.public_key() != expected_public_key:
            raise PeerVerificationError(
                f"Certificate public key mismatch: expected {expected_public_key},"
                f"{certificate.public_key()} in the certificate")

        secure_contact = SecureContact.checked(contact, certificate)

        return cls._checked(metadata, payload, clock, secure_contact)

    def __init__(self, metadata: NodeMetadata, secure_contact):
        self.metadata = metadata
        self.secure_contact = secure_contact


class PeerPrivateKey:

    def __init__(self, seed: bytes):
        self.__seed = seed

    def as_ssl_private_key(self):
        return SSLPrivateKey.from_seed(self.__seed)


class PeerPublicKey:

    def __init__(self, certificate):
        self._certificate = certificate

    def __bytes__(self):
        return self._certificate.to_der_bytes()
