from contextlib import asynccontextmanager
import http
import httpx

from .certificate import SSLCertificate, fetch_certificate
from .protocol import Metadata, ContactPackage, SignedContact, ContactRequest
from .utils import temp_file, Contact, SSLContact


class HttpError(Exception):

    def __init__(self, message, status_code):
        super().__init__(message)
        self.status_code = status_code


@asynccontextmanager
async def async_client_ssl(certificate: SSLCertificate):
    # TODO: avoid saving the certificate to disk at each request,
    # and keep them in a directory somewhere.
    with temp_file(certificate.to_pem_bytes()) as f:
        async with httpx.AsyncClient(verify=f.name) as client:
            yield client


class NetworkMiddleware:
    """
    The job of NetworkMiddleware is to send the request to the correct endpoint of the server,
    and then convert the response to either the returned raw data or HttpError,
    depending on the status.
    """

    async def fetch_certificate(self, contact):
        return await fetch_certificate(contact.host, contact.port)

    @staticmethod
    def _unwrap_json(response):
        if not response.status_code == http.HTTPStatus.OK:
            raise HttpError(response, response.status_code)
        return response.json()

    async def ping(self, ssl_contact: SSLContact):
        async with async_client_ssl(ssl_contact.certificate) as client:
            response = await client.get(ssl_contact.url + '/ping')
        return self._unwrap_json(response)

    async def get_contacts(self, ssl_contact: SSLContact, contact_request_json):
        async with async_client_ssl(ssl_contact.certificate) as client:
            response = await client.get(ssl_contact.url + '/get_contacts', json=contact_request_json)
        return self._unwrap_json(response)


class MockMiddleware:
    """
    A counterpart of NetworkMiddleware with raw data/response pass-through directly to the server.
    """

    def __init__(self):
        self._known_servers = {}

    def add_server(self, ursula_server):
        self._known_servers[ursula_server.ssl_contact.contact] = ursula_server

    async def fetch_certificate(self, contact: Contact):
        server = self._known_servers[contact]
        return server.ssl_contact.certificate

    async def ping(self, ssl_contact: SSLContact):
        server = self._known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact.certificate
        return await server.endpoint_ping()

    async def get_contacts(self, ssl_contact: SSLContact, contact_request_json):
        server = self._known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact.certificate
        return await server.endpoint_get_contacts(contact_request_json)


class NetworkClient:
    """
    The client's job is to serialize the arguments, deserialize the result,
    catch HttpError from middleware and convert it to more specific exceptions -
    the callers shouldn't worry about HTTP status codes.
    """

    def __init__(self, middleware):
        self._middleware = middleware

    async def fetch_certificate(self, contact: Contact) -> SSLContact:
        certificate = await self._middleware.fetch_certificate(contact)
        return SSLContact(contact, certificate)

    async def ping(self, ssl_contact: SSLContact) -> Metadata:
        try:
            metadata_json = await self._middleware.ping(ssl_contact)
        except HttpError as e:
            raise RuntimeError(e) from e
        return Metadata.from_json(metadata_json)

    async def get_contacts(self, ssl_contact: SSLContact, contact_request: ContactRequest) -> ContactPackage:
        try:
            contact_package_json = await self._middleware.get_contacts(ssl_contact, contact_request.to_json())
        except HttpError as e:
            raise RuntimeError(e) from e
        return ContactPackage.from_json(contact_package_json)

    async def reencrypt_dkg(self, ssl_contact: SSLContact, capsule, key_bits):
        # FIXME: DKG object serialization is not implemented yet,
        # so this request doesn't go into the middleware per se,
        # we're assuming that we have `MockMiddleware` and get an `UrsulaServer` from it.
        server = self._middleware._known_servers[ssl_contact.contact]
        return await server.endpoint_reencrypt_dkg(capsule, key_bits)
