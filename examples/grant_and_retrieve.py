import os
from typing import NamedTuple, Tuple, List

import trio
import trio.testing
from eth_account import Account
from hexbytes import HexBytes

from nucypher_async.characters import Ursula
from nucypher_async.server import UrsulaServer, UrsulaServerConfig
from nucypher_async.p2p.learner import Learner
from nucypher_async.drivers.identity import IdentityClient, IdentityAccount, AmountT
from nucypher_async.drivers.payment import PaymentClient, PaymentAccount
from nucypher_async.drivers.http_server import HTTPServerHandle
from nucypher_async.drivers.peer import Contact, PeerClient, UrsulaHTTPServer
from nucypher_async.storage import InMemoryStorage
from nucypher_async.base.time import BaseClock
from nucypher_async.drivers.time import SystemClock
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient, MockClock
from nucypher_async.domain import Domain
from nucypher_async.client.pre import (
    Alice,
    Bob,
    RemoteAlice,
    RemoteBob,
    encrypt,
    MessageKit,
    Policy,
)
from nucypher_async.utils.logging import Logger, ConsoleHandler, Level


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
    payment_client: PaymentClient
    clock: BaseClock


async def run_local_ursula_fleet(
    context: Context, nursery: trio.Nursery
) -> Tuple[List[HTTPServerHandle], Contact]:

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

        config = UrsulaServerConfig(
            domain=context.domain,
            contact=Contact(LOCALHOST, PORT_BASE + i),
            identity_client=context.identity_client,
            payment_client=context.payment_client,
            peer_client=PeerClient(),
            parent_logger=context.logger.get_child(f"Ursula{i+1}"),
            storage=InMemoryStorage(),
            seed_contacts=seed_contacts,
            clock=context.clock,
        )

        server = await UrsulaServer.async_init(ursula, config)
        handle = HTTPServerHandle(UrsulaHTTPServer(server))
        await nursery.start(handle)
        handles.append(handle)

    return handles, Contact(LOCALHOST, PORT_BASE)


async def alice_grants(
    context: Context, seed_contact: Contact, alice: Alice, remote_bob: RemoteBob
) -> Tuple[RemoteAlice, Policy]:

    learner = Learner(
        identity_client=context.identity_client,
        domain=context.domain,
        parent_logger=context.logger.get_child("Learner-Alice"),
        seed_contacts=[seed_contact],
        clock=context.clock,
    )

    # Fill out the node database so that we had something to work with
    await learner.seed_round()
    await learner.verification_round()

    policy = await alice.grant(
        learner=learner,
        payment_client=context.payment_client,
        bob=remote_bob,
        label=b"label-" + os.urandom(8).hex().encode(),
        threshold=2,
        shares=3,
    )

    return alice.public_info(), policy


async def bob_decrypts(
    context: Context,
    seed_contact: Contact,
    bob: Bob,
    remote_alice: RemoteAlice,
    policy: Policy,
    message_kit: MessageKit,
) -> bytes:

    learner = Learner(
        identity_client=context.identity_client,
        domain=context.domain,
        parent_logger=context.logger.get_child("Learner-Bob"),
        seed_contacts=[seed_contact],
        clock=context.clock,
    )

    decrypted = await bob.retrieve_and_decrypt(
        learner=learner,
        message_kit=message_kit,
        encrypted_treasure_map=policy.encrypted_treasure_map,
        remote_alice=remote_alice,
    )

    return decrypted


async def main(mocked: bool = True) -> None:

    logger = Logger(handlers=[ConsoleHandler(level=Level.INFO)])
    domain = Domain.IBEX

    if mocked:
        context = Context(
            logger=logger,
            domain=domain,
            identity_client=MockIdentityClient(),
            payment_client=MockPaymentClient(),
            clock=MockClock(),
        )
    else:
        context = Context(
            logger=logger,
            domain=domain,
            identity_client=IdentityClient.from_endpoint(RINKEBY_ENDPOINT, Domain.IBEX),
            payment_client=PaymentClient.from_endpoint(MUMBAI_ENDPOINT, Domain.IBEX),
            clock=SystemClock(),
        )

    async with trio.open_nursery() as nursery:
        if mocked:
            context.logger.info("Mocked mode - starting Ursulas")
            server_handles, seed_contact = await run_local_ursula_fleet(context, nursery)
            # Wait for all the nodes to learn about each other
            await trio.sleep(3600)
        else:
            seed_contact = Contact("ibex.nucypher.network", 9151)

        bob = Bob()
        remote_bob = bob.public_info()

        if mocked:
            payment_account = PaymentAccount.random()
        else:
            # TODO: don't expose eth_account.Account
            acc = Account.from_key(
                HexBytes(
                    b"$\x88O\xf4\xaf\xc13Ol\xce\xe6\x89\xcc\xeb.\x9bD)Zu\xb3\x95I\xce\xa4\xc4-\xfd\x85+\x9an"
                )
            )
            payment_account = PaymentAccount(acc)

        alice = Alice(payment_account=payment_account)

        context.logger.info("Alice grants")
        remote_alice, policy = await alice_grants(context, seed_contact, alice, remote_bob)

        message = b"a secret message"
        message_kit = encrypt(policy.encrypting_key, message)

        context.logger.info("Bob retrieves")
        decrypted = await bob_decrypts(
            context, seed_contact, bob, remote_alice, policy, message_kit
        )

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
