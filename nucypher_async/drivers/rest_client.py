"""
The job of the REST dirver is to encapsulate dealing with the specific request library
(currently ``httpx``), extract request data and convert status codes to exceptions.
It is the "client" countrerpart of ``rest_app``.
"""

from contextlib import asynccontextmanager
import http
import httpx

from .errors import HTTPError
from .ssl import SSLCertificate, fetch_certificate
from ..utils import temp_file


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


@asynccontextmanager
async def async_client_ssl(certificate: SSLCertificate):
    # TODO: avoid saving the certificate to disk at each request,
    # and keep them in a directory somewhere.
    with temp_file(certificate.to_pem_bytes()) as f:
        async with httpx.AsyncClient(verify=f.name) as client:
            yield client


def unwrap_json(response):
    if not response.status_code == http.HTTPStatus.OK:
        raise HTTPError(response, response.status_code)
    return response.json()


class RESTClient:

    async def fetch_certificate(self, contact: Contact):
        return await fetch_certificate(contact.host, contact.port)

    async def ping(self, ssl_contact: SSLContact):
        async with async_client_ssl(ssl_contact.certificate) as client:
            response = await client.get(ssl_contact.url + '/ping')
        return unwrap_json(response)

    async def get_contacts(self, ssl_contact: SSLContact, contact_request_json):
        async with async_client_ssl(ssl_contact.certificate) as client:
            response = await client.get(ssl_contact.url + '/get_contacts', json=contact_request_json)
        return unwrap_json(response)
