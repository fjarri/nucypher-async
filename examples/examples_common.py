# noqa: INP001

from dataclasses import dataclass

import trio
import trio.testing
from eth_account import Account
from hexbytes import HexBytes

from nucypher_async._drivers.http_client import HTTPClient
from nucypher_async._drivers.ssl import fetch_certificate
from nucypher_async._drivers.time import SystemClock
from nucypher_async.base.time import BaseClock
from nucypher_async.blockchain.cbd import CBDClient
from nucypher_async.blockchain.identity import AmountT, IdentityAccount, IdentityClient
from nucypher_async.blockchain.pre import PREAccount, PREClient
from nucypher_async.characters.cbd import Decryptor
from nucypher_async.characters.pre import Reencryptor
from nucypher_async.domain import Domain
from nucypher_async.master_key import MasterKey
from nucypher_async.mocks import MockCBDClient, MockClock, MockIdentityClient, MockPREClient
from nucypher_async.node import HTTPServerConfig, NodeServer, NodeServerConfig, NodeServerHandle
from nucypher_async.p2p import Contact, NodeClient, Operator
from nucypher_async.utils.logging import ConsoleHandler, Level, Logger

LOCALHOST = "127.0.0.1"
PORT_BASE = 9151

GOERLI_ENDPOINT = "<rinkeby endpoint address here>"
MUMBAI_ENDPOINT = "https://rpc-mumbai.matic.today/"
RINKEBY_ENDPOINT = "<rinkeby endpoint address here>"


@dataclass
class Context:
    logger: Logger
    domain: Domain
    identity_client: IdentityClient
    pre_client: PREClient
    cbd_client: CBDClient
    clock: BaseClock
    seed_contact: Contact
    server_handles: list[NodeServerHandle]
    pre_account: PREAccount

    @classmethod
    async def local(cls, nursery: trio.Nursery) -> "Context":
        handles = []

        domain = Domain.TAPIR
        logger = Logger(handlers=[ConsoleHandler(level=Level.INFO)])
        identity_client = MockIdentityClient()
        pre_client = MockPREClient()
        cbd_client = MockCBDClient()
        clock = MockClock()

        logger.info("Mocked mode - starting nodes")

        for i in range(3):
            master_key = MasterKey.random()
            identity_account = IdentityAccount.random()
            operator = Operator(master_key, identity_account)
            reencryptor = Reencryptor(master_key)
            decryptor = Decryptor(master_key)

            # Make the first node the dedicated teacher of the other nodes
            seed_contacts = [Contact(LOCALHOST, PORT_BASE)] if i > 0 else []

            # Initialize the newly created staking provider and operator
            staking_provider_account = IdentityAccount.random()
            identity_client.mock_set_up(
                staking_provider_account.address,
                operator.address,
                AmountT.ether(40000),
            )

            logger = logger.get_child(f"Node{i + 1}")

            http_server_config = HTTPServerConfig.from_typed_values(
                bind_to_address=LOCALHOST,
                bind_to_port=PORT_BASE + i,
            )

            config = NodeServerConfig.from_typed_values(
                http_server_config=http_server_config,
                domain=domain,
                identity_client=identity_client,
                pre_client=pre_client,
                cbd_client=cbd_client,
                node_client=NodeClient(HTTPClient()),
                logger=logger,
                seed_contacts=seed_contacts,
                clock=clock,
            )

            server = await NodeServer.async_init(
                config=config,
                operator=operator,
                reencryptor=reencryptor,
                decryptor=decryptor,
            )

            handle = NodeServerHandle(server)
            await nursery.start(handle.startup)
            handles.append(handle)

            # Make sure the HTTP server is operational before proceeding
            await fetch_certificate(LOCALHOST, PORT_BASE + i)

        await trio.sleep(1)

        return cls(
            logger=logger,
            domain=domain,
            identity_client=identity_client,
            pre_client=pre_client,
            cbd_client=cbd_client,
            clock=clock,
            seed_contact=Contact(LOCALHOST, PORT_BASE),
            server_handles=handles,
            pre_account=PREAccount.random(),
        )

    @classmethod
    def tapir(cls) -> "Context":
        logger = Logger(handlers=[ConsoleHandler(level=Level.INFO)])
        # TODO: don't expose eth_account.Account
        acc = Account.from_key(
            HexBytes(
                b"$\x88O\xf4\xaf\xc13Ol\xce\xe6\x89\xcc\xeb.\x9bD)Zu\xb3\x95I\xce\xa4\xc4-\xfd\x85+\x9an"
            )
        )

        return cls(
            logger=logger,
            domain=Domain.TAPIR,
            identity_client=IdentityClient.from_endpoint(RINKEBY_ENDPOINT, Domain.TAPIR),
            pre_client=PREClient.from_endpoint(MUMBAI_ENDPOINT, Domain.TAPIR),
            cbd_client=CBDClient.from_endpoint(MUMBAI_ENDPOINT, Domain.TAPIR),
            seed_contact=Contact("tapir.nucypher.network", 9151),
            clock=SystemClock(),
            pre_account=PREAccount(acc),
            server_handles=[],
        )
