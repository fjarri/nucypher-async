"""
The job of the REST dirver is to encapsulate dealing with the specific request library
(currently ``httpx``), extract request data and convert status codes to exceptions.
It is the "client" countrerpart of ``rest_app``.
"""

from contextlib import asynccontextmanager
import http
from ipaddress import IPv4Address, AddressValueError

import httpx
from nucypher_core import (
    NodeMetadata, MetadataRequest, MetadataResponse, ReencryptionRequest, ReencryptionResponse)

from .ssl import SSLCertificate, fetch_certificate
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


class SSLContact:

    def __init__(self, contact: Contact, certificate: SSLCertificate):
        self.contact = contact
        self.certificate = certificate

    @classmethod
    def from_metadata(cls, metadata: NodeMetadata):
        return cls(
            Contact.from_metadata(metadata),
            SSLCertificate.from_der_bytes(metadata.payload.certificate_der))

    def __eq__(self, other):
        return self.contact == other.contact and self.certificate == other.certificate

    @property
    def url(self):
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


class RESTClient:

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

    async def handshake(self, contact: Contact) -> SSLContact:
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

        if certificate.declared_host != resolved_contact.host:
            raise HandshakeError(
                f"Host mismatch: contact has {contact.host}, "
                f"but certificate has {certificate.declared_host}")

        return SSLContact(contact, certificate)

    async def ping(self, ssl_contact: SSLContact) -> str:
        async with self._http_client(ssl_contact.certificate) as client:
            response = await client.get(ssl_contact.url + '/ping')
        return response.text

    async def node_metadata_post(self, ssl_contact: SSLContact, metadata_request: MetadataRequest):
        async with self._http_client(ssl_contact.certificate) as client:
            response = await client.post(ssl_contact.url + '/node_metadata', data=bytes(metadata_request))
        return unwrap_bytes(response, MetadataResponse)

    async def public_information(self, ssl_contact: SSLContact):
        async with self._http_client(ssl_contact.certificate) as client:
            response = await client.get(ssl_contact.url + '/public_information')
        return unwrap_bytes(response, NodeMetadata)

    async def reencrypt(self, ssl_contact: SSLContact, reencryption_request: ReencryptionRequest):
        async with self._http_client(ssl_contact.certificate) as client:
            response = await client.post(ssl_contact.url + '/reencrypt', data=bytes(reencryption_request))
        return unwrap_bytes(response, ReencryptionResponse)
