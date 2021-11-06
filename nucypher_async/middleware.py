import http
import httpx

from .metadata import FleetState, Metadata


class HttpError(Exception):

    def __init__(self, message, status_code):
        super().__init__(message)
        self.status_code = status_code


class NetworkMiddleware:
    """
    The job of NetworkMiddleware is to send the request to the correct endpoint of the server,
    and then convert the response to either the returned raw data or HttpError,
    depending on the status.
    """

    @staticmethod
    def _unwrap_json(response):
        if not response.status_code == http.HTTPStatus.OK:
            raise HttpError(response, response.status_code)
        return response.json()

    async def ping(self, address):
        async with httpx.AsyncClient() as client:
            response = await client.post('http://' + address + '/ping')
        return self._unwrap_json(response)

    async def exchange_metadata(self, address, state_json):
        async with httpx.AsyncClient() as client:
            response = await client.post('http://' + address + '/exchange_metadata', json=state.to_json())
        return self._unwrap_json(response)


class MockMiddleware:
    """
    A counterpart of NetworkMiddleware with raw data/response pass-through directly to the server.
    """

    def __init__(self):
        self._known_servers = {}

    def add_server(self, address, ursula_server):
        self._known_servers[address] = ursula_server

    async def ping(self, address):
        server = self._known_servers[address]
        return await server.endpoint_ping()

    async def exchange_metadata(self, address, state_json):
        server = self._known_servers[address]
        return await server.endpoint_exchange_metadata(state_json)


class NetworkClient:
    """
    The client's job is to serialize the arguments, deserialize the result,
    catch HttpError from middleware and convert it to more specific exceptions -
    the callers shouldn't worry about HTTP status codes.
    """

    def __init__(self, middleware):
        self._middleware = middleware

    async def ping(self, address) -> Metadata:
        try:
            metadata_json = await self._middleware.ping(address)
        except HttpError as e:
            raise RuntimeError(e)
        return Metadata.from_json(metadata_json)

    async def exchange_metadata(self, address, state: FleetState) -> FleetState:
        try:
            state_json = await self._middleware.exchange_metadata(address, state.to_json())
        except HttpError as e:
            raise RuntimeError(e)
        return FleetState.from_json(state_json)

    async def reencrypt_dkg(self, address, capsule, key_bits):
        # FIXME: DKG object serialization is not implemented yet,
        # so this request doesn't go into the middleware per se,
        # we're assuming that we have `MockMiddleware` and get an `UrsulaServer` from it.
        server = self._middleware._known_servers[address]
        return await server.endpoint_reencrypt_dkg(capsule, key_bits)
