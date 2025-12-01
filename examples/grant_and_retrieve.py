# noqa: INP001

import functools
import os
from typing import NamedTuple

import trio
from eth_account import Account
from hexbytes import HexBytes

from nucypher_async.base.time import BaseClock
from nucypher_async.characters.cbd import Decryptor
from nucypher_async.characters.node import Operator
from nucypher_async.characters.pre import Delegator, Publisher, Recipient, Reencryptor
from nucypher_async.client.network import NetworkClient
from nucypher_async.client.pre import LocalPREClient, pre_encrypt
from nucypher_async.domain import Domain
from nucypher_async.drivers.cbd import CBDClient
from nucypher_async.drivers.identity import AmountT, IdentityAccount, IdentityClient
from nucypher_async.drivers.peer import Contact, PeerClient, PeerServerHandle
from nucypher_async.drivers.pre import PREAccount, PREAccountSigner, PREClient
from nucypher_async.drivers.time import SystemClock
from nucypher_async.master_key import MasterKey
from nucypher_async.mocks import MockCBDClient, MockClock, MockIdentityClient, MockPREClient
from nucypher_async.node import HTTPServerConfig, NodeServer, NodeServerConfig
from nucypher_async.utils.logging import ConsoleHandler, Level, Logger
from nucypher_async.utils.ssl import fetch_certificate

LOCALHOST = "127.0.0.1"
PORT_BASE = 9151

RINKEBY_ENDPOINT = "<rinkeby endpoint address here>"
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


# TODO: move to a separate module to use in other examples
async def run_local_node_fleet(
    context: Context, nursery: trio.Nursery
) -> tuple[list[PeerServerHandle], Contact]:
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

        logger = context.logger.get_child(f"Node{i + 1}")

        http_server_config = HTTPServerConfig.from_typed_values(
            bind_to_address=LOCALHOST,
            bind_to_port=PORT_BASE + i,
        )

        config = NodeServerConfig.from_typed_values(
            http_server_config=http_server_config,
            domain=context.domain,
            identity_client=context.identity_client,
            pre_client=context.pre_client,
            cbd_client=context.cbd_client,
            peer_client=PeerClient(),
            logger=logger,
            seed_contacts=seed_contacts,
            clock=context.clock,
        )

        server = await NodeServer.async_init(
            config=config,
            operator=operator,
            reencryptor=reencryptor,
            decryptor=decryptor,
        )

        handle = PeerServerHandle(server)
        await nursery.start(handle.startup)
        handles.append(handle)

        # Make sure the HTTP server is operational before proceeding
        await fetch_certificate(LOCALHOST, PORT_BASE + i)

    return handles, Contact(LOCALHOST, PORT_BASE)


async def main(*, mocked: bool = True) -> None:
    logger = Logger(handlers=[ConsoleHandler(level=Level.INFO)])
    domain = Domain.TAPIR

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
            identity_client=IdentityClient.from_endpoint(RINKEBY_ENDPOINT, Domain.TAPIR),
            pre_client=PREClient.from_endpoint(MUMBAI_ENDPOINT, Domain.TAPIR),
            cbd_client=CBDClient.from_endpoint(MUMBAI_ENDPOINT, Domain.TAPIR),
            clock=SystemClock(),
        )

    async with trio.open_nursery() as nursery:
        if mocked:
            context.logger.info("Mocked mode - starting nodes")
            server_handles, seed_contact = await run_local_node_fleet(context, nursery)
            # Wait for all the nodes to learn about each other
            await trio.sleep(1)
        else:
            seed_contact = Contact("tapir.nucypher.network", 9151)

        if mocked:
            pre_account = PREAccount.random()
        else:
            # TODO: don't expose eth_account.Account
            acc = Account.from_key(
                HexBytes(
                    b"$\x88O\xf4\xaf\xc13Ol\xce\xe6\x89\xcc\xeb.\x9bD)Zu\xb3\x95I\xce\xa4\xc4-\xfd\x85+\x9an"
                )
            )
            pre_account = PREAccount(acc)
        publisher_signer = PREAccountSigner(pre_account)

        bob = Recipient(MasterKey.random())
        alice = Delegator(MasterKey.random())
        publisher = Publisher(MasterKey.random())

        publisher_client = LocalPREClient(
            NetworkClient(
                domain=context.domain,
                identity_client=context.identity_client,
                seed_contacts=[seed_contact],
                parent_logger=context.logger.get_child("Publisher"),
                clock=context.clock,
            ),
            context.pre_client,
        )

        bob_client = LocalPREClient(
            NetworkClient(
                domain=context.domain,
                identity_client=context.identity_client,
                seed_contacts=[seed_contact],
                parent_logger=context.logger.get_child("Recipient"),
                clock=context.clock,
            ),
            context.pre_client,
        )

        context.logger.info("Alice creates policy")
        policy = alice.make_policy(
            recipient_card=bob.card(),
            label=b"label-" + os.urandom(8).hex().encode(),
            threshold=2,
            shares=3,
        )

        context.logger.info("Publisher publishes policy")
        enacted_policy = await publisher_client.grant(
            publisher, publisher_signer, policy, bob.card()
        )

        message = b"a secret message"
        message_kit = pre_encrypt(enacted_policy, message)

        context.logger.info("Bob retrieves and decrypts")
        decrypted = await bob_client.decrypt(
            bob,
            enacted_policy,
            message_kit,
            alice.card(),
            publisher.card(),
        )

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
