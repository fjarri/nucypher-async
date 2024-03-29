from typing import List

import trio
import trio.testing

from nucypher_async.server import UrsulaServer


async def test_learning(
    nursery: trio.Nursery,
    autojump_clock: trio.testing.MockClock,
    chain_seeded_ursulas: List[UrsulaServer],
) -> None:
    while True:
        # Wait multiple learning cycles
        # TODO: find a way to wait until the learning is done, and measure how much time has passed
        await trio.sleep(100)

        known_nodes = {
            server._node.staking_provider_address: server.learner.get_verified_ursulas(
                include_this_node=True
            )
            for server in chain_seeded_ursulas
        }

        # Each Ursula should know about every other Ursula by now.
        if all(len(nodes) == 10 for nodes in known_nodes.values()):
            break
