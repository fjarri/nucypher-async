import httpx

from .metadata import FleetState, Metadata


class NetworkMiddleware:

    async def ping(self, address):
        async with httpx.AsyncClient() as client:
            response = await client.post('http://' + address + '/ping')

        if not response.status_code == 200:
            raise RuntimeError(response)

        return Metadata.from_json(response.json())

    async def exchange_metadata(self, address, state: FleetState) -> FleetState:
        async with httpx.AsyncClient() as client:
            response = await client.post('http://' + address + '/exchange_metadata', json=state.to_json())

        if not response.status_code == 200:
            raise RuntimeError(response)

        state = FleetState.from_json(response.json())

        return state


class MockMiddleware:

    def __init__(self):
        self._known_servers = {}

    def add_server(self, address, ursula_server):
        self._known_servers[address] = ursula_server

    async def ping(self, address):
        server = self._known_servers[address]
        return await server.endpoint_ping()

    async def exchange_metadata(self, address, payload):
        server = self._known_servers[address]
        return await server.endpoint_exchange_metadata(payload)

    async def reencrypt_dkg(self, address, capsule, key_bits):
        server = self._known_servers[address]
        return await server.endpoint_reencrypt_dkg(capsule, key_bits)
