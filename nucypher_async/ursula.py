import time
import random

import httpx
import trio


from .middleware import NetworkMiddleware
from .metadata import Metadata, FleetState


class Ursula:

    def __init__(self, id):
        self.id = id
        self.started = time.time()

    def metadata(self, address):
        return Metadata(id=self.id, address=address)


class Learner:
    """
    The client for P2P network of Ursulas, keeping the metadata of known nodes
    and running the background learning task.
    """

    def __init__(self, middleware, my_metadata=None, seed_addresses=[]):
        self._middleware = middleware
        self.seed_addresses = seed_addresses
        self.my_metadata = my_metadata
        self.nodes = {}

        self._nodes_updated = trio.Event()
        self._task_learning = None

    def start(self, nursery):
        assert not self._task_learning
        self._task_learning = BackgroundTask(nursery, self.learn)

    def stop(self):
        assert self._task_learning
        self._task_learning.stop()
        self._task_learning = None

    def __del__(self):
        if self._task_learning:
            self.stop()

    async def remember_nodes(self, state: FleetState):
        for id, metadata in state.nodes.items():
            if self.my_metadata and id == self.my_metadata.id:
                continue
            self.nodes[id] = metadata

        # Release whoever was waiting for the state to be updated
        self._nodes_updated.set()
        await trio.sleep(0)
        self._nodes_updated = trio.Event()

    def current_state(self):
        nodes = dict(self.nodes)
        if self.my_metadata:
            nodes[self.my_metadata.id] = self.my_metadata
        return FleetState(nodes)

    async def knows_nodes(self, ursula_ids):
        ids_set = set(ursula_ids)
        while True:
            if ids_set.issubset(self.nodes):
                return {id: self.nodes[id].address for id in ids_set}
            await self._nodes_updated.wait()

    async def learn(self, this_task):

        before = set(self.nodes)

        addresses = [node.address for node in self.nodes.values()] + self.seed_addresses
        if len(addresses) == 0:
            # Nowhere to learn from
            return

        teacher_address = random.choice(addresses)

        remote_state = await self._middleware.exchange_metadata(teacher_address, self.current_state())

        await self.remember_nodes(remote_state)
        await this_task.restart_in(10)


class BackgroundTask:

    def __init__(self, nursery, task_callable):
        self._nursery = nursery
        self._task_callable = task_callable
        self._shutdown_event = trio.Event()

        self._nursery.start_soon(self._task_callable, self)

    async def restart_in(self, timeout):
        with trio.move_on_after(timeout):
            await self._shutdown_event.wait()
            return
        self._nursery.start_soon(self._task_callable, self)

    def stop(self):
        self._shutdown_event.set()


class HttpError(Exception):

    def __init__(self, message, status_code):
        super().__init__(message)
        self.status_code = status_code


class UrsulaServer:

    def __init__(self, ursula, middleware=None, port=9151, host='localhost', seed_addresses=[]):

        self.port = port
        self.host = host
        self.address = f"{host}:{port}"

        if middleware is None:
            middleware = NetworkMiddleware()

        self.ursula = ursula
        self.learner = Learner(middleware, self.ursula.metadata(self.address), seed_addresses)

        self.started = False

    def start(self, nursery):
        assert not self.started

        # TODO: make sure a proper cleanup happens if the start-up fails halfway
        self.learner.start(nursery)

        self.started = True

    def stop(self):
        assert self.started

        self.learner.stop()

        self.started = False

    async def endpoint_ping(self):
        return self.ursula.metadata(self.address)

    async def endpoint_exchange_metadata(self, state: FleetState):
        await self.learner.remember_nodes(state)
        return self.learner.current_state()
