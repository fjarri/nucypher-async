from collections.abc import Iterable

import trio

from ..base.time import BaseClock
from ..domain import Domain
from ..drivers.identity import IdentityAddress, IdentityClient
from ..drivers.peer import Contact, PeerClient
from ..drivers.time import SystemClock
from ..p2p.algorithms import (
    learning_task,
    random_verified_nodes_iter,
    staker_query_task,
    verification_task,
    verified_nodes_iter,
)
from ..p2p.fleet_sensor import FleetSensorSnapshot
from ..p2p.learner import Learner
from ..p2p.verification import VerifiedNodeInfo
from ..storage import BaseStorage
from ..utils.logging import NULL_LOGGER, Logger


class NetworkClient:
    def __init__(
        self,
        identity_client: IdentityClient,
        peer_client: PeerClient | None = None,
        seed_contacts: Iterable[Contact] | None = None,
        domain: Domain = Domain.MAINNET,
        parent_logger: Logger = NULL_LOGGER,
        clock: BaseClock = SystemClock(),
        storage: BaseStorage | None = None,
    ):
        self._learner = Learner(
            peer_client=peer_client or PeerClient(),
            identity_client=identity_client,
            domain=domain,
            parent_logger=parent_logger.get_child("NetworkClient"),
            seed_contacts=seed_contacts,
            clock=clock,
            storage=storage,
        )
        self._seeded = False

    @property
    def clock(self) -> BaseClock:
        return self._learner.clock

    def get_snapshot(self) -> FleetSensorSnapshot:
        return self._learner.get_snapshot()

    async def _get_updated_learner(self) -> Learner:
        await self._ensure_seeded()
        return self._learner

    async def _ensure_seeded(self) -> None:
        if not self._seeded:
            await self._learner.seed_round()
            self._seeded = True

    async def verification_task(self, stop_event: trio.Event) -> None:
        await verification_task(stop_event, self._learner)

    async def learning_task(self, stop_event: trio.Event) -> None:
        await learning_task(stop_event, self._learner)

    async def staker_query_task(self, stop_event: trio.Event) -> None:
        await staker_query_task(stop_event, self._learner)

    async def get_nodes(
        self,
        quantity: int,
        include_nodes: Iterable[IdentityAddress] | None = None,
        exclude_nodes: Iterable[IdentityAddress] | None = None,
    ) -> list[VerifiedNodeInfo]:
        await self._ensure_seeded()

        nodes = []

        include = set(include_nodes) if include_nodes else set()
        exclude = set(exclude_nodes) if exclude_nodes else set()

        # Note: include_nodes takes priority over exclude_nodes
        async with verified_nodes_iter(self._learner, include, verified_within=60) as node_iter:
            async for node in node_iter:
                nodes.append(node)

        if len(nodes) < quantity:
            quantity_remaining = quantity - len(nodes)
            overhead = max(1, quantity_remaining // 5)
            async with random_verified_nodes_iter(
                learner=self._learner,
                amount=quantity_remaining,
                overhead=overhead,
                verified_within=60,
                exclude_nodes=exclude | include,
            ) as node_iter:
                async for node in node_iter:
                    nodes.append(node)

        return nodes
