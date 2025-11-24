# noqa: INP001

import functools
from typing import NamedTuple

import trio
import trio.testing

from nucypher_async.base.time import BaseClock
from nucypher_async.characters.cbd import Decryptor, Encryptor
from nucypher_async.characters.node import Operator
from nucypher_async.characters.pre import Reencryptor
from nucypher_async.client.cbd import ThresholdMessageKit, cbd_decrypt, initiate_ritual
from nucypher_async.client.network import NetworkClient
from nucypher_async.domain import Domain
from nucypher_async.drivers.cbd import CBDClient
from nucypher_async.drivers.http_server import HTTPServerHandle
from nucypher_async.drivers.identity import AmountT, IdentityAccount, IdentityClient
from nucypher_async.drivers.peer import Contact, PeerClient
from nucypher_async.drivers.pre import PREClient
from nucypher_async.drivers.time import SystemClock
from nucypher_async.master_key import MasterKey
from nucypher_async.mocks import MockCBDClient, MockClock, MockIdentityClient, MockPREClient
from nucypher_async.server import NodeServer, NodeServerConfig, PeerServerConfig
from nucypher_async.storage import InMemoryStorage
from nucypher_async.utils.logging import ConsoleHandler, Level, Logger
from nucypher_async.utils.ssl import fetch_certificate

LOCALHOST = "127.0.0.1"
PORT_BASE = 9151

GOERLI_ENDPOINT = "<rinkeby endpoint address here>"
MUMBAI_ENDPOINT = "https://rpc-mumbai.matic.today/"


# Information shared by all parties
# (Easier than passing endless lists of arguments)
class Context(NamedTuple):
    logger: Logger
    domain: Domain
    identity_client: IdentityClient
    pre_client: PREClient
    cbd_client: CBDClient
    clock: BaseClock


async def run_local_node_fleet(
    context: Context, nursery: trio.Nursery
) -> tuple[list[HTTPServerHandle], Contact]:
    handles = []
    for i in range(3):
        master_key = MasterKey.random()
        identity_account = IdentityAccount.random()
        operator = Operator(master_key, identity_account)
        reencryptor = Reencryptor(master_key)
        decryptor = Decryptor(master_key)

        # Make the first node the dedicated teacher of the other nodes
        seed_contacts = [Contact(LOCALHOST, PORT_BASE)] if i > 0 else []

        assert isinstance(context.identity_client, MockIdentityClient)

        # Initialize the newly created staking provider and operator
        staking_provider_account = IdentityAccount.random()
        context.identity_client.mock_set_up(
            staking_provider_account.address,
            operator.address,
            AmountT.ether(40000),
        )

        peer_server_config = PeerServerConfig.from_typed_values(
            external_host=LOCALHOST,
            external_port=PORT_BASE + i,
        )

        config = NodeServerConfig(
            domain=context.domain,
            identity_client=context.identity_client,
            pre_client=context.pre_client,
            cbd_client=context.cbd_client,
            peer_client=PeerClient(),
            parent_logger=context.logger.get_child(f"Ursula{i + 1}"),
            storage=InMemoryStorage(),
            seed_contacts=seed_contacts,
            clock=context.clock,
        )

        server = await NodeServer.async_init(
            operator=operator,
            reencryptor=reencryptor,
            decryptor=decryptor,
            peer_server_config=peer_server_config,
            config=config,
        )
        handle = HTTPServerHandle(server)
        await nursery.start(handle.startup)
        handles.append(handle)

        # Make sure the HTTP server is operational before proceeding
        await fetch_certificate(LOCALHOST, PORT_BASE + i)

    return handles, Contact(LOCALHOST, PORT_BASE)


async def bob_decrypts(
    context: Context,
    seed_contact: Contact,
    message_kit: ThresholdMessageKit,
) -> bytes:
    network_client = NetworkClient(
        identity_client=context.identity_client,
        domain=context.domain,
        parent_logger=context.logger.get_child("Bob"),
        seed_contacts=[seed_contact],
        clock=context.clock,
    )

    return await cbd_decrypt(network_client, message_kit=message_kit, cbd_client=context.cbd_client)


async def main(*, mocked: bool = True) -> None:
    logger = Logger(handlers=[ConsoleHandler(level=Level.INFO)])
    domain = Domain.LYNX

    if mocked:
        context = Context(
            logger=logger,
            domain=domain,
            identity_client=MockIdentityClient(),
            pre_client=MockPREClient(),
            cbd_client=MockCBDClient(),
            clock=MockClock(),
        )
    else:
        context = Context(
            logger=logger,
            domain=domain,
            identity_client=IdentityClient.from_endpoint(GOERLI_ENDPOINT, domain),
            pre_client=PREClient.from_endpoint(MUMBAI_ENDPOINT, domain),
            cbd_client=CBDClient.from_endpoint(MUMBAI_ENDPOINT, domain),
            clock=SystemClock(),
        )

    async with trio.open_nursery() as nursery:
        if mocked:
            context.logger.info("Mocked mode - starting Ursulas")
            server_handles, seed_contact = await run_local_node_fleet(context, nursery)
            # Wait for all the nodes to learn about each other
            await trio.sleep(1)
        else:
            seed_contact = Contact("lynx.nucypher.network", 9151)

        alice_keys = MasterKey.random()
        alice = Encryptor(alice_keys)

        network_client = NetworkClient(
            identity_client=context.identity_client,
            domain=context.domain,
            parent_logger=context.logger.get_child("Alice"),
            seed_contacts=[seed_contact],
            clock=context.clock,
        )
        ritual = await initiate_ritual(network_client, context.cbd_client, 3)

        context.logger.info("Alice encrypts")
        message = b"a secret message"
        message_kit = alice.encrypt(ritual.public_key, message)

        context.logger.info("Bob decrypts")
        decrypted = await bob_decrypts(context, seed_contact, message_kit)

        assert message == decrypted
        context.logger.info("Message decrypted successfully!")

        if mocked:
            context.logger.info("Stopping nodes")
            for handle in server_handles:
                await handle.shutdown()


def run_main(*, mocked: bool = True) -> None:
    trio.run(functools.partial(main, mocked=mocked))


if __name__ == "__main__":
    run_main()
