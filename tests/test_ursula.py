import os

import pytest
import trio

from nucypher_async.drivers.identity import IdentityAddress, AmountT
from nucypher_async.drivers.peer import Contact, PeerHTTPServer
from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.config import UrsulaServerConfig
from nucypher_async.domain import Domain
from nucypher_async.storage import InMemoryStorage
from nucypher_async.learner import Learner
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient, MockPeerClient


async def test_learning(nursery, autojump_clock, chain_seeded_ursulas):

    while True:
        # Wait multiple learning cycles
        # TODO: find a way to wait until the learning is done, and measure how much time has passed
        await trio.sleep(100)

        known_nodes = {
            server._node.staking_provider_address: server.learner.metadata_to_announce()
            for server in chain_seeded_ursulas
        }

        # Each Ursula should know about every other Ursula by now.
        if all(len(nodes) == 10 for nodes in known_nodes.values()):
            break
