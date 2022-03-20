import os
from typing import NamedTuple

import trio
from eth_account import Account

from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.learner import Learner
from nucypher_async.drivers.identity import IdentityClient, IdentityAccount, AmountT
from nucypher_async.drivers.payment import PaymentClient, PaymentAccount
from nucypher_async.drivers.rest_server import start_in_nursery
from nucypher_async.drivers.rest_client import Contact
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient
from nucypher_async.pre import Alice, Bob, RemoteAlice, RemoteBob, encrypt
from nucypher_async.utils.logging import Logger, ConsoleHandler, Level


LOCAL_DOMAIN = "local"
LOCALHOST = '127.0.0.1'
PORT_BASE = 9151

RINKEBY_ENDPOINT = "https://rinkeby.infura.io/v3/e86a8c23df63469ab91d5b40fbff09d1"
MUMBAI_ENDPOINT = "https://rpc-mumbai.matic.today/"


# Information shared by all parties
# (Easier than passing endless lists of arguments)
class Context(NamedTuple):
    logger: Logger
    domain: str
    identity_client: IdentityClient
    payment_client: PaymentClient
    seed_contact: Contact


async def run_local_ursula_fleet(context, nursery):

    handles = []
    contacts = []
    for i in range(3):
        # Since private keys are not given explicitly, they will be created at random
        ursula = Ursula(domain=context.domain)

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

        server = await UrsulaServer.async_init(
            ursula=ursula,
            identity_client=context.identity_client,
            payment_client=context.payment_client,
            parent_logger=context.logger.get_child(f"Ursula{i+1}"),
            host=LOCALHOST,
            port=PORT_BASE + i,
            seed_contacts=seed_contacts,
            learning_timeout=1,
            )

        handle = start_in_nursery(nursery, server)
        handles.append(handle)

    return handles, Contact(LOCALHOST, PORT_BASE)


async def alice_grants(context, alice, remote_bob):

    learner = Learner(
        identity_client=context.identity_client,
        domain=context.domain,
        parent_logger=context.logger.get_child("Learner-Alice"),
        seed_contacts=[context.seed_contact])

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
        seed_contacts=[context.seed_contact])

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
        seed_contact=None)

    if mocked:
        context = context._replace(
            domain=LOCAL_DOMAIN,
            identity_client=MockIdentityClient(),
            payment_client=MockPaymentClient())
    else:
        context = context._replace(
            domain='ibex',
            identity_client=IdentityClient.from_http_endpoint(RINKEBY_ENDPOINT),
            payment_client=PaymentClient.from_http_endpoint(MUMBAI_ENDPOINT))

    async with trio.open_nursery() as nursery:
        if mocked:
            context.logger.info("Mocked mode - starting Ursulas")
            server_handles, seed_contact = await run_local_ursula_fleet(context, nursery)
        else:
            seed_contact = Contact('ibex.nucypher.network', 9151)

        context = context._replace(seed_contact=seed_contact)

        bob = Bob()
        remote_bob = bob.public_info()

        if mocked:
            payment_account = PaymentAccount.random()
        else:
            # TODO: don't expose eth_account.Account
            acc = Account.from_key(b'<your Mumbai private key here>')
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


if __name__ == '__main__':
    trio.run(main)
