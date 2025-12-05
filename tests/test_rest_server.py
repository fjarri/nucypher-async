import os

import pytest
import trio

from nucypher_async._drivers.http_client import HTTPClient
from nucypher_async.blockchain.identity import IdentityAccount, IdentityAddress
from nucypher_async.characters.cbd import Decryptor
from nucypher_async.characters.pre import Reencryptor
from nucypher_async.domain import Domain
from nucypher_async.master_key import MasterKey
from nucypher_async.mocks import MockCBDClient, MockIdentityClient, MockPREClient
from nucypher_async.node import HTTPServerConfig, NodeServer, NodeServerConfig, NodeServerHandle
from nucypher_async.p2p import NodeClient, Operator
from nucypher_async.utils.logging import NULL_LOGGER


@pytest.fixture
def node_server() -> NodeServer:
    http_server_config = HTTPServerConfig.from_typed_values(
        bind_to_address="127.0.0.1",
        bind_to_port=9151,
    )
    config = NodeServerConfig.from_typed_values(
        http_server_config=http_server_config,
        domain=Domain.MAINNET,
        identity_client=MockIdentityClient(),
        pre_client=MockPREClient(),
        cbd_client=MockCBDClient(),
        logger=NULL_LOGGER,
        seed_contacts=[],
    )

    master_key = MasterKey.random()
    identity_account = IdentityAccount.random()
    operator = Operator(master_key, identity_account)
    reencryptor = Reencryptor(master_key)
    decryptor = Decryptor(master_key)

    return NodeServer(
        config=config,
        operator=operator,
        reencryptor=reencryptor,
        decryptor=decryptor,
        staking_provider_address=IdentityAddress(os.urandom(20)),
    )


async def test_client_real_server(nursery: trio.Nursery, node_server: NodeServer) -> None:
    handle = NodeServerHandle(node_server)
    await nursery.start(handle.startup)

    client = NodeClient(HTTPClient())
    response = await client.ping(node_server.secure_contact())
    assert response == "127.0.0.1"

    response = await client.status(node_server.secure_contact())

    await handle.shutdown()
