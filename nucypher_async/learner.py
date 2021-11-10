import enum
import random

import trio

from .certificate import fetch_certificate
from .metadata import FleetState
from .middleware import NetworkClient, ConnectionInfo
from .utils import BackgroundTask


class Learner:
    """
    The client for P2P network of Ursulas, keeping the metadata of known nodes
    and running the background learning task.
    """

    def __init__(self, middleware, my_metadata=None, seed_addresses=[]):
        self._client = NetworkClient(middleware)
        self._seed_addresses = seed_addresses
        self._my_metadata = my_metadata

        self._nodes = {} # To be moved to FleetSensor?

        self._nodes_updated = trio.Event()

    async def remember_nodes(self, new_state):

        for id, metadata in new_state.nodes.items():
            # We know better what our metadata is
            if self._my_metadata and id == self._my_metadata.id:
                continue
            self._nodes[id] = metadata

        # Release whoever was waiting for the state to be updated
        # TODO: only do so if there was a change in the state.
        self._nodes_updated.set()
        await trio.sleep(0) # TODO: is it necessary?
        self._nodes_updated = trio.Event()

    def current_state(self):
        nodes = dict(self._nodes)
        if self._my_metadata:
            nodes[self._my_metadata.id] = self._my_metadata
        return FleetState(nodes)

    async def knows_nodes(self, ursula_ids):
        ids_set = set(ursula_ids)
        while True:
            if ids_set.issubset(self._nodes):
                return {id: self._nodes[id] for id in ids_set}
            await self._nodes_updated.wait()

    async def learn_from_random_seed_node(self):

        host, port = self._seed_addresses.pop()
        certificate = await self._client._middleware.fetch_certificate(host, port)
        cinfo = ConnectionInfo(host, port, certificate)

        remote_state = await self._client.exchange_metadata(cinfo, self.current_state())

        await self.remember_nodes(remote_state)

    async def learn_from_random_node(self):

        node_ids = list(self._nodes)
        teacher_id = random.choice(node_ids)
        teacher = self._nodes[teacher_id]

        remote_state = await self._client.exchange_metadata(teacher.connection_info, self.current_state())

        await self.remember_nodes(remote_state)

    async def learning_round(self):
        if self._seed_addresses:
            await self.learn_from_random_seed_node()
        elif self._nodes:
            await self.learn_from_random_node()
        else:
            raise RuntimeError("No nodes to learn from")
