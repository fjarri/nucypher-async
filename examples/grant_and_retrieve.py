import os
from typing import NamedTuple

import trio
from eth_account import Account

from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.learner import Learner
from nucypher_async.config import UrsulaServerConfig
from nucypher_async.drivers.identity import IdentityClient, IdentityAccount, AmountT
from nucypher_async.drivers.payment import PaymentClient, PaymentAccount
from nucypher_async.drivers.rest_server import ServerHandle
from nucypher_async.drivers.rest_client import Contact, RESTClient
from nucypher_async.storage import InMemoryStorage
from nucypher_async.drivers.time import Clock, SystemClock
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient, MockClock
from nucypher_async.domain import Domain
from nucypher_async.pre import Alice, Bob, RemoteAlice, RemoteBob, encrypt
from nucypher_async.utils.logging import Logger, ConsoleHandler, Level


LOCALHOST = '127.0.0.1'
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
    seed_contact: Contact
    clock: Clock


async def run_local_ursula_fleet(context, nursery):

    handles = []
    contacts = []
    for i in range(3):
        # Since private keys are not given explicitly, they will be created at random
        ursula = Ursula()

        # Make the first node the dedicated teacher of the other nodes
        if i > 0:
            seed_contacts = [Contact(LOCALHOST, PORT_BASE)]
        else:
            seed_contacts = []

        # Initialize the newly created staking provider and operator
        staking_provider_account = IdentityAccount.random()
        context.identity_client.mock_approve(staking_provider_account.address, AmountT.ether(40000))
        context.identity_client.mock_stake(staking_provider_account.address, AmountT.ether(40000))
        context.identity_client.mock_bond_operator(staking_provider_account.address, ursula.operator_address)
        # TODO: UrsulaServer should do it on startup
        context.identity_client.mock_confirm_operator(ursula.operator_address)


        config = UrsulaServerConfig(
            domain=context.domain,
            contact=Contact(LOCALHOST, PORT_BASE + i),
            identity_client=context.identity_client,
            payment_client=context.payment_client,
            rest_client=RESTClient(),
            parent_logger=context.logger.get_child(f"Ursula{i+1}"),
            storage=InMemoryStorage(),
            seed_contacts=seed_contacts,
            clock=context.clock,
            )

        server = await UrsulaServer.async_init(ursula, config)
        handle = ServerHandle(server)
        await nursery.start(handle)
        handles.append(handle)

    return handles, Contact(LOCALHOST, PORT_BASE)


async def alice_grants(context, alice, remote_bob):

    learner = Learner(
        identity_client=context.identity_client,
        domain=context.domain,
        parent_logger=context.logger.get_child("Learner-Alice"),
        seed_contacts=[context.seed_contact],
        clock=context.clock)

    policy = await alice.grant(
        learner=learner,
        payment_client=context.payment_client,
        bob=remote_bob,
        label=b'label-' + os.urandom(8).hex().encode(),
        threshold=2,
        shares=3)

    return alice.public_info(), policy


async def bob_decrypts(context, bob, remote_alice, policy, message_kit):

    learner = Learner(
        identity_client=context.identity_client,
        domain=context.domain,
        parent_logger=context.logger.get_child('Learner-Bob'),
        seed_contacts=[context.seed_contact],
        clock=context.clock)

    decrypted = await bob.retrieve_and_decrypt(
        learner=learner,
        message_kit=message_kit,
        encrypted_treasure_map=policy.encrypted_treasure_map,
        remote_alice=remote_alice)

    return decrypted


async def main(mocked=True):

    context = Context(
        logger=Logger(handlers=[ConsoleHandler(level=Level.INFO)]),
        domain=None,
        identity_client=None,
        payment_client=None,
        seed_contact=None,
        clock=None)

    if mocked:
        context = context._replace(
            domain=Domain.IBEX,
            identity_client=MockIdentityClient(),
            payment_client=MockPaymentClient(),
            clock=MockClock())
    else:
        context = context._replace(
            domain=Domain.IBEX,
            identity_client=IdentityClient.from_endpoint(RINKEBY_ENDPOINT, Domain.IBEX),
            payment_client=PaymentClient.from_endpoint(MUMBAI_ENDPOINT, Domain.IBEX),
            clock=SystemClock())

    async with trio.open_nursery() as nursery:
        if mocked:
            context.logger.info("Mocked mode - starting Ursulas")
            server_handles, seed_contact = await run_local_ursula_fleet(context, nursery)
            # Wait for all the nodes to learn about each other
            await trio.sleep(3600)
        else:
            seed_contact = Contact('ibex.nucypher.network', 9151)

        context = context._replace(seed_contact=seed_contact)

        bob = Bob()
        remote_bob = bob.public_info()

        if mocked:
            payment_account = PaymentAccount.random()
        else:
            # TODO: don't expose eth_account.Account
            acc = Account.from_key(b'$\x88O\xf4\xaf\xc13Ol\xce\xe6\x89\xcc\xeb.\x9bD)Zu\xb3\x95I\xce\xa4\xc4-\xfd\x85+\x9an')
            payment_account = PaymentAccount(acc)

        alice = Alice(payment_account=payment_account)

        context.logger.info("Alice grants")
        remote_alice, policy = await alice_grants(context, alice, remote_bob)

        message = b'a secret message'
        message_kit = encrypt(policy.encrypting_key, message)

        context.logger.info("Bob retrieves")
        decrypted = await bob_decrypts(context, bob, remote_alice, policy, message_kit)

        assert message == decrypted
        context.logger.info("Message decrypted successfully!")

        if mocked:
            context.logger.info("Stopping Ursulas")
            for handle in server_handles:
                handle.shutdown()


def run_main(mocked=True):
    if mocked:
        from trio.testing import MockClock
        clock = MockClock(autojump_threshold=0)
    else:
        clock = None

    trio.run(main, mocked, clock=clock)


if __name__ == '__main__':
    run_main()
