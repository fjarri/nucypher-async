import trio

from ..node import NodeServer
from ..node.handle import NodeServerAsHTTPServer
from ..node_base import Contact, PeerPublicKey
from ..p2p import NodeClient
from .asgi import MockHTTPClient, MockHTTPNetwork, MockHTTPServerHandle


class MockNodeServerHandle:
    def __init__(self, handle: MockHTTPServerHandle):
        self._handle = handle

    async def startup(self) -> None:
        await self._handle.startup()

    async def shutdown(self) -> None:
        await self._handle.shutdown()


class MockP2PNetwork:
    def __init__(self, nursery: trio.Nursery):
        self._mock_http_network = MockHTTPNetwork(nursery)

    def add_server(self, server: NodeServer) -> MockNodeServerHandle:
        handle = self._mock_http_network.add_server(NodeServerAsHTTPServer(server))
        return MockNodeServerHandle(handle)

    async def startup(self, contact: Contact) -> None:
        await self._mock_http_network.startup(contact.host, contact.port)

    async def shutdown(self, contact: Contact) -> None:
        await self._mock_http_network.shutdown(contact.host, contact.port)

    def get_public_key(self, contact: Contact) -> PeerPublicKey:
        certificate, _manager = self._mock_http_network.get_server(contact.host, contact.port)
        return PeerPublicKey(certificate)


# Note that we cannot just use `NodeClient(mock_http_client)` since we need the client
# to be able to supply its own host in requests
# (which nodes use to filter the received contact list).
class MockNodeClient(NodeClient):
    def __init__(self, mock_p2p_network: MockP2PNetwork, contact: Contact | None = None):
        super().__init__(
            MockHTTPClient(
                mock_p2p_network._mock_http_network,  # noqa: SLF001
                contact.host if contact else None,
            )
        )
