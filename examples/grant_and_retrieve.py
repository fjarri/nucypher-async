import os
from typing import NamedTuple, Tuple, List

import trio
import trio.testing
from eth_account import Account
from hexbytes import HexBytes

from nucypher_async.master_key import MasterKey
from nucypher_async.characters.pre import (
    Ursula,
    Delegator,
    Recipient,
    DelegatorCard,
    RecipientCard,
    Publisher,
    PublisherCard,
    Policy,
)
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
    encrypt,
    grant,
    retrieve_and_decrypt,
    MessageKit,
    EnactedPolicy,
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
        await nursery.start(handle.startup)
        handles.append(handle)

    return handles, Contact(LOCALHOST, PORT_BASE)


async def alice_grants(
    context: Context,
    seed_contact: Contact,
    delegator: Delegator,
    publisher: Publisher,
    recipient_card: RecipientCard,
) -> EnactedPolicy:
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

    policy = delegator.make_policy(
        recipient_card=recipient_card,
        label=b"label-" + os.urandom(8).hex().encode(),
        threshold=2,
        shares=3,
    )

    return await grant(
        policy=policy,
        recipient_card=recipient_card,
        publisher=publisher,
        learner=learner,
        payment_client=context.payment_client,
    )


async def bob_decrypts(
    context: Context,
    seed_contact: Contact,
    recipient: Recipient,
    delegator_card: DelegatorCard,
    publisher_card: PublisherCard,
    enacted_policy: EnactedPolicy,
    message_kit: MessageKit,
) -> bytes:
    learner = Learner(
        identity_client=context.identity_client,
        domain=context.domain,
        parent_logger=context.logger.get_child("Learner-Bob"),
        seed_contacts=[seed_contact],
        clock=context.clock,
    )

    decrypted = await retrieve_and_decrypt(
        client=learner,
        message_kits=[message_kit],
        enacted_policy=enacted_policy,
        delegator_card=delegator_card,
        recipient=recipient,
        publisher_card=publisher_card,
    )

    return decrypted[0]


async def main(mocked: bool = True) -> None:
    logger = Logger(handlers=[ConsoleHandler(level=Level.INFO)])
    domain = Domain.TAPIR

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
            identity_client=IdentityClient.from_endpoint(RINKEBY_ENDPOINT, Domain.TAPIR),
            payment_client=PaymentClient.from_endpoint(MUMBAI_ENDPOINT, Domain.TAPIR),
            clock=SystemClock(),
        )

    async with trio.open_nursery() as nursery:
        if mocked:
            context.logger.info("Mocked mode - starting Ursulas")
            server_handles, seed_contact = await run_local_ursula_fleet(context, nursery)
            # Wait for all the nodes to learn about each other
            await trio.sleep(3600)
        else:
            seed_contact = Contact("tapir.nucypher.network", 9151)

        bob_keys = MasterKey.random()
        bob = Recipient(bob_keys)

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

        alice_keys = MasterKey.random()
        alice = Delegator(alice_keys)
        publisher_keys = MasterKey.random()
        publisher = Publisher(publisher_keys, payment_account)

        context.logger.info("Alice grants")
        policy = await alice_grants(context, seed_contact, alice, publisher, bob.card())

        message = b"a secret message"
        message_kit = encrypt(policy, message)

        context.logger.info("Bob retrieves")
        decrypted = await bob_decrypts(
            context, seed_contact, bob, alice.card(), publisher.card(), policy, message_kit
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
