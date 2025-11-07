import os
from ipaddress import IPv4Address

import pytest
import trio

from nucypher_async.characters.cbd import Decryptor
from nucypher_async.characters.node import Operator
from nucypher_async.characters.pre import Reencryptor
from nucypher_async.domain import Domain
from nucypher_async.drivers.http_server import HTTPServerHandle
from nucypher_async.drivers.identity import IdentityAccount, IdentityAddress
from nucypher_async.drivers.peer import Contact, PeerClient
from nucypher_async.drivers.time import SystemClock
from nucypher_async.master_key import MasterKey
from nucypher_async.mocks import MockCBDClient, MockIdentityClient, MockPREClient
from nucypher_async.p2p.node_info import NodeClient
from nucypher_async.server import NodeServer, NodeServerConfig, PeerServerConfig
from nucypher_async.storage import InMemoryStorage
from nucypher_async.utils.logging import NULL_LOGGER


@pytest.fixture
def node_server() -> NodeServer:
    peer_server_config = PeerServerConfig(
        bind_to=IPv4Address("127.0.0.1"),
        contact=Contact("127.0.0.1", 9151),
        ssl_certificate=None,
        ssl_private_key=None,
        ssl_ca_chain=None,
    )
    config = NodeServerConfig(
        domain=Domain.MAINNET,
        identity_client=MockIdentityClient(),
        pre_client=MockPREClient(),
        cbd_client=MockCBDClient(),
        peer_client=PeerClient(),
        parent_logger=NULL_LOGGER,
        storage=InMemoryStorage(),
        seed_contacts=[],
        clock=SystemClock(),
    )

    master_key = MasterKey.random()
    identity_account = IdentityAccount.random()
    operator = Operator(master_key, identity_account)
    reencryptor = Reencryptor(master_key)
    decryptor = Decryptor(master_key)

    return NodeServer(
        operator=operator,
        reencryptor=reencryptor,
        decryptor=decryptor,
        peer_server_config=peer_server_config,
        config=config,
        staking_provider_address=IdentityAddress(os.urandom(20)),
    )


async def test_client_real_server(
    nursery: trio.Nursery,
    capsys: pytest.CaptureFixture[str],
    node_server: NodeServer,
) -> None:
    handle = HTTPServerHandle(node_server)
    await nursery.start(handle.startup)

    client = NodeClient(PeerClient())
    response = await client.ping(node_server.secure_contact())
    assert response == "127.0.0.1"

    response = await client.status(node_server.secure_contact())

    await handle.shutdown()
    capsys.readouterr()
