import trio
import trio.testing

from nucypher_async.node import NodeServer


async def test_learning(
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
    chain_seeded_nodes: list[NodeServer],
) -> None:
    # Wait multiple learning cycles
    while True:
        await trio.sleep(100)
        if all(server.learner.has_no_new_contacts() for server in chain_seeded_nodes):
            break

    known_nodes = {
        server.info.staking_provider_address: server.learner.get_verified_nodes()
        for server in chain_seeded_nodes
    }

    # Each node should know about every other node by now.
    assert all(len(nodes) == 9 for nodes in known_nodes.values())
