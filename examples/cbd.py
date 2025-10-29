from typing import NamedTuple

import trio
import trio.testing
from eth_account import Account
from hexbytes import HexBytes

from nucypher_async.base.time import BaseClock
from nucypher_async.characters.cbd import CBDEncryptor
from nucypher_async.characters.pre import Ursula
from nucypher_async.client.cbd import ThresholdMessageKit, cbd_decrypt, initiate_ritual
from nucypher_async.domain import Domain
from nucypher_async.drivers.http_server import HTTPServerHandle
from nucypher_async.drivers.identity import AmountT, IdentityAccount, IdentityClient
from nucypher_async.drivers.peer import Contact, PeerClient, UrsulaHTTPServer
from nucypher_async.drivers.pre import PREAccount, PREClient
from nucypher_async.drivers.time import SystemClock
from nucypher_async.master_key import MasterKey
from nucypher_async.mocks import MockClock, MockIdentityClient, MockPREClient
from nucypher_async.p2p.learner import Learner
from nucypher_async.server import UrsulaServer, UrsulaServerConfig, PeerServerConfig
from nucypher_async.storage import InMemoryStorage
from nucypher_async.utils.logging import ConsoleHandler, Level, Logger

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
    cbd_client: CBDClient
    clock: BaseClock


async def run_local_ursula_fleet(
    context: Context, nursery: trio.Nursery
) -> tuple[list[HTTPServerHandle], Contact]:
    handles = []
    for i in range(3):
        # Since private keys are not given explicitly, they will be created at random
        ursula = Ursula()

        # Make the first node the dedicated teacher of the other nodes
        if i > 0:
            seed_contacts = [Contact(LOCALHOST, PORT_BASE)]
        else:
            seed_contacts = []

        assert isinstance(context.identity_client, MockIdentityClient)

        # Initialize the newly created staking provider and operator
        staking_provider_account = IdentityAccount.random()
        context.identity_client.mock_set_up(
            staking_provider_account.address,
            ursula.operator_address,
            AmountT.ether(40000),
        )

        peer_server_config = PeerServerConfig(
            bind_as="127.0.0.1",
            contact=Contact(LOCALHOST, PORT_BASE + i),
            ssl_certificate=None,
            ssl_private_key=None,
            ssl_ca_chain=None,
        )

        config = UrsulaServerConfig(
            domain=context.domain,
            identity_client=context.identity_client,
            cbd_client=context.cbd_client,
            peer_client=PeerClient(),
            parent_logger=context.logger.get_child(f"Ursula{i + 1}"),
            storage=InMemoryStorage(),
            seed_contacts=seed_contacts,
            clock=context.clock,
        )

        server = await UrsulaServer.async_init(ursula, peer_server_config=peer_server_config, config=config)
        handle = HTTPServerHandle(UrsulaHTTPServer(server))
        await nursery.start(handle.startup)
        handles.append(handle)

    return handles, Contact(LOCALHOST, PORT_BASE)


async def bob_decrypts(
    context: Context,
    seed_contact: Contact,
    message_kit: ThresholdMessageKit,
) -> bytes:
    learner = Learner(
        identity_client=context.identity_client,
        domain=context.domain,
        parent_logger=context.logger.get_child("Learner-Bob"),
        seed_contacts=[seed_contact],
        clock=context.clock,
    )

    decrypted = await cbd_decrypt(
        learner=learner, message_kit=message_kit, cbd_client=context.cbd_client
    )

    return decrypted


async def main(mocked: bool = True) -> None:
    logger = Logger(handlers=[ConsoleHandler(level=Level.INFO)])
    domain = Domain.LYNX

    if mocked:
        context = Context(
            logger=logger,
            domain=domain,
            identity_client=MockIdentityClient(),
            cbd_client=MockPREClient(),
            clock=MockClock(),
        )
    else:
        context = Context(
            logger=logger,
            domain=domain,
            identity_client=IdentityClient.from_endpoint(GOERLI_ENDPOINT, domain),
            cbd_client=PREClient.from_endpoint(MUMBAI_ENDPOINT, domain),
            clock=SystemClock(),
        )

    async with trio.open_nursery() as nursery:
        if mocked:
            context.logger.info("Mocked mode - starting Ursulas")
            server_handles, seed_contact = await run_local_ursula_fleet(context, nursery)
            # Wait for all the nodes to learn about each other
            await trio.sleep(3600)
        else:
            seed_contact = Contact("lynx.nucypher.network", 9151)

        alice_keys = MasterKey.random()
        alice = CBDEncryptor(alice_keys)

        learner = Learner(
            identity_client=context.identity_client,
            domain=context.domain,
            parent_logger=context.logger.get_child("Learner-Alice"),
            seed_contacts=[seed_contact],
            clock=context.clock,
        )
        ritual = await initiate_ritual(learner, context.cbd_client, 3)

        context.logger.info("Alice encrypts")
        message = b"a secret message"
        message_kit = alice.encrypt(ritual.public_key, message)

        context.logger.info("Bob decrypts")
        decrypted = await bob_decrypts(context, seed_contact, message_kit)

        assert message == decrypted
        context.logger.info("Message decrypted successfully!")

        if mocked:
            context.logger.info("Stopping Ursulas")
            for handle in server_handles:
                await handle.shutdown()


def run_main(mocked: bool = True) -> None:
    if mocked:
        clock = trio.testing.MockClock(autojump_threshold=0)
        trio.run(main, mocked, clock=clock)
    else:
        trio.run(main, mocked)


if __name__ == "__main__":
    run_main()
