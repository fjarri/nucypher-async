# noqa: INP001

import functools

import trio
import trio.testing
from examples_common import Context

from nucypher_async.characters.cbd import Encryptor
from nucypher_async.client.cbd import LocalCBDClient
from nucypher_async.client.network import NetworkClient
from nucypher_async.drivers.cbd import CBDAccount, CBDAccountSigner
from nucypher_async.master_key import MasterKey


async def main(*, mocked: bool = True) -> None:
    async with trio.open_nursery() as nursery:
        if mocked:
            context = await Context.local(nursery)
        else:
            context = Context.tapir()

        ritualist_signer = CBDAccountSigner(CBDAccount.random())

        alice_keys = MasterKey.random()
        alice = Encryptor(alice_keys)

        ritualist_client = LocalCBDClient(
            NetworkClient(
                identity_client=context.identity_client,
                domain=context.domain,
                parent_logger=context.logger.get_child("Ritualist"),
                seed_contacts=[context.seed_contact],
                clock=context.clock,
            ),
            context.cbd_client,
        )
        ritual = await ritualist_client.initiate_ritual(
            ritualist_signer, shares=3, duration=24 * 60 * 60
        )

        context.logger.info("Alice encrypts")
        message = b"a secret message"
        message_kit = alice.encrypt(ritual.public_key, message)

        context.logger.info("Bob decrypts")

        bob_client = LocalCBDClient(
            NetworkClient(
                identity_client=context.identity_client,
                domain=context.domain,
                parent_logger=context.logger.get_child("Bob"),
                seed_contacts=[context.seed_contact],
                clock=context.clock,
            ),
            context.cbd_client,
        )
        decrypted = await bob_client.decrypt(message_kit)

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
