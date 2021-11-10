from contextlib import contextmanager
import http
import httpx

from .certificate import SSLCertificate, fetch_certificate
from .metadata import FleetState, Metadata, ConnectionInfo
from .utils import temp_file


class HttpError(Exception):

    def __init__(self, message, status_code):
        super().__init__(message)
        self.status_code = status_code


@contextmanager
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

    async def fetch_certificate(self, host, port):
        return await fetch_certificate(host, port)

    @staticmethod
    def _unwrap_json(response):
        if not response.status_code == http.HTTPStatus.OK:
            raise HttpError(response, response.status_code)
        return response.json()

    async def ping(self, cinfo: ConnectionInfo, certificate: SSLCertificate):
        async with async_client_ssl(certificate) as client:
            response = await client.post(cinfo.url + '/ping')
        return self._unwrap_json(response)

    async def exchange_metadata(self, cinfo: ConnectionInfo, state_json):
        async with async_client_ssl(certificate) as client:
            response = await client.post(cinfo.url + '/exchange_metadata', json=state.to_json())
        return self._unwrap_json(response)


class MockMiddleware:
    """
    A counterpart of NetworkMiddleware with raw data/response pass-through directly to the server.
    """

    def __init__(self):
        self._known_servers = {}

    def add_server(self, ursula_server):
        self._known_servers[(ursula_server.host, ursula_server.port)] = ursula_server

    async def fetch_certificate(self, host, port):
        server = self._known_servers[(host, port)]
        return server.ssl_certificate

    async def ping(self, cinfo):
        server = self._known_servers[(cinfo.host, cinfo.port)]
        assert cinfo.certificate == server.ssl_certificate
        return await server.endpoint_ping()

    async def exchange_metadata(self, cinfo, state_json):
        server = self._known_servers[(cinfo.host, cinfo.port)]
        assert cinfo.certificate == server.ssl_certificate
        return await server.endpoint_exchange_metadata(state_json)


class NetworkClient:
    """
    The client's job is to serialize the arguments, deserialize the result,
    catch HttpError from middleware and convert it to more specific exceptions -
    the callers shouldn't worry about HTTP status codes.
    """

    def __init__(self, middleware):
        self._middleware = middleware

    async def ping(self, cinfo: ConnectionInfo) -> Metadata:
        try:
            metadata_json = await self._middleware.ping(cinfo)
        except HttpError as e:
            raise RuntimeError(e)
        return Metadata.from_json(metadata_json)

    async def exchange_metadata(self, cinfo: ConnectionInfo, state: FleetState) -> FleetState:
        try:
            state_json = await self._middleware.exchange_metadata(cinfo, state.to_json())
        except HttpError as e:
            raise RuntimeError(e)
        return FleetState.from_json(state_json)

    async def reencrypt_dkg(self, cinfo: ConnectionInfo, capsule, key_bits):
        # FIXME: DKG object serialization is not implemented yet,
        # so this request doesn't go into the middleware per se,
        # we're assuming that we have `MockMiddleware` and get an `UrsulaServer` from it.
        server = self._middleware._known_servers[(cinfo.host, cinfo.port)]
        return await server.endpoint_reencrypt_dkg(capsule, key_bits)
