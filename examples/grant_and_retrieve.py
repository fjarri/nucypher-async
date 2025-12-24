# noqa: INP001

import functools
import os

import trio
from examples_common import Context

from nucypher_async.blockchain.pre import PREAccountSigner
from nucypher_async.characters import MasterKey
from nucypher_async.characters.pre import Delegator, EncryptedMessage, Publisher, Recipient
from nucypher_async.client.network import NetworkClient
from nucypher_async.client.pre import LocalPREClient


async def main(*, mocked: bool = True) -> None:
    async with trio.open_nursery() as nursery:
        if mocked:
            context = await Context.local(nursery)
        else:
            context = Context.tapir()

        publisher_signer = PREAccountSigner(context.pre_account)

        bob = Recipient(MasterKey.random())
        alice = Delegator(MasterKey.random())
        publisher = Publisher(MasterKey.random())

        publisher_client = LocalPREClient(
            NetworkClient(
                domain=context.domain,
                identity_client=context.identity_client,
                seed_contacts=[context.seed_contact],
                parent_logger=context.logger.get_child("Publisher"),
                clock=context.clock,
            ),
            context.pre_client,
        )

        bob_client = LocalPREClient(
            NetworkClient(
                domain=context.domain,
                identity_client=context.identity_client,
                seed_contacts=[context.seed_contact],
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
        encrypted_message = EncryptedMessage(enacted_policy.policy, message)

        context.logger.info("Bob retrieves and decrypts")
        decrypted = await bob_client.decrypt(
            bob,
            enacted_policy,
            encrypted_message,
            alice.card(),
            publisher.card(),
        )

        assert message == decrypted
        context.logger.info("Message decrypted successfully!")

        if mocked:
            context.logger.info("Stopping nodes")
            for handle in context.server_handles:
                await handle.shutdown()


def run_main(*, mocked: bool = True) -> None:
    trio.run(functools.partial(main, mocked=mocked))


if __name__ == "__main__":
    run_main()
