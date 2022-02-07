"""
The job of the REST dirver is to encapsulate dealing with the specific request library
(currently ``httpx``), extract request data and convert status codes to exceptions.
It is the "client" countrerpart of ``rest_app``.
"""

from contextlib import asynccontextmanager
import http
import httpx

from nucypher_core import NodeMetadata

from .errors import HTTPError
from .ssl import SSLCertificate, fetch_certificate
from ..utils import temp_file


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
        assert certificate.declared_host == contact.host

        self.contact = contact
        self.certificate = certificate

    @classmethod
    def from_metadata(cls, metadata: NodeMetadata):
        return cls(
            Contact.from_metadata(metadata),
            SSLCertificate.from_pem_bytes(metadata.payload.certificate_bytes))

    def __eq__(self, other):
        return self.contact == other.contact and self.certificate == other.certificate

    @property
    def url(self):
        return f"https://{self.contact.host}:{self.contact.port}"


@asynccontextmanager
async def async_client_ssl(certificate: SSLCertificate):
    # TODO: avoid saving the certificate to disk at each request,
    # and keep them in a directory somewhere.
    with temp_file(certificate.to_pem_bytes()) as filename:
        async with httpx.AsyncClient(verify=filename) as client:
            yield client


def unwrap_bytes(response):
    if not response.status_code == http.HTTPStatus.OK:
        raise HTTPError(response, response.status_code)
    return response.data()


class RESTClient:

    async def fetch_certificate(self, contact: Contact):
        return await fetch_certificate(contact.host, contact.port)

    async def ping(self, ssl_contact: SSLContact):
        async with async_client_ssl(ssl_contact.certificate) as client:
            response = await client.get(ssl_contact.url + '/ping')
        return response.data()

    async def node_metadata_post(self, ssl_contact: SSLContact, metadata_request_bytes):
        async with async_client_ssl(ssl_contact.certificate) as client:
            response = await client.get(ssl_contact.url + '/node_metadata', data=metadata_request_bytes)
        return unwrap_bytes(response)

    async def public_information(self, ssl_contact):
        async with async_client_ssl(ssl_contact.certificate) as client:
            response = await client.get(ssl_contact.url + '/public_information')
        return unwrap_bytes(response)

    async def reencrypt(self, ssl_contact: SSLContact, reencryption_request_bytes):
        async with async_client_ssl(ssl_contact.certificate) as client:
            response = await client.get(ssl_contact.url + '/reencrypt', data=reencryption_request_bytes)
        return unwrap_bytes(response)
