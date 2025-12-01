import trio
import trio.testing

from nucypher_async.node import NodeServer


async def test_learning(
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
    chain_seeded_nodes: list[NodeServer],
) -> None:
    while True:
        # Wait multiple learning cycles
        # TODO: find a way to wait until the learning is done, and measure how much time has passed
        await trio.sleep(100)

        known_nodes = {
            server._node.staking_provider_address: server.learner.get_verified_nodes()
            for server in chain_seeded_nodes
        }

        # Each node should know about every other node by now.
        if all(len(nodes) == 9 for nodes in known_nodes.values()):
            break
