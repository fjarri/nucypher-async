from bisect import bisect_right
from itertools import accumulate
import datetime
import random
from typing import (
    TypeVar,
    Generic,
    Sequence,
    Callable,
    Awaitable,
    Iterable,
    Optional,
    Mapping,
    List,
)

import trio

from ..drivers.identity import IdentityAddress
from ..utils import wait_for_any
from ..utils.producer import producer
from .fleet_sensor import NodeEntry, StakingProviderEntry
from .learner import Learner
from .verification import VerifiedUrsulaInfo


WeightedReservoirT = TypeVar("WeightedReservoirT")


class WeightedReservoir(Generic[WeightedReservoirT]):
    def __init__(
        self,
        elements: Sequence[WeightedReservoirT],
        get_weight: Callable[[WeightedReservoirT], int],
    ):
        weights = [get_weight(elem) for elem in elements]
        self.totals = list(accumulate(weights))
        self.elements = elements
        self._length = len(elements)

    def draw(self) -> WeightedReservoirT:
        # TODO: can we use floats instead, so that we don't have to round the stakes to integer T?
        position = random.randint(0, self.totals[-1] - 1)
        idx = bisect_right(self.totals, position)
        sample = self.elements[idx]

        # Adjust the totals so that they correspond
        # to the weight of the element `idx` being set to 0.
        prev_total = self.totals[idx - 1] if idx > 0 else 0
        weight = self.totals[idx] - prev_total
        for j in range(idx, len(self.totals)):
            self.totals[j] -= weight

        self._length -= 1

        return sample

    def __len__(self) -> int:
        return self._length


async def verification_task(stop_event: trio.Event, learner: Learner) -> None:
    while True:
        await learner.verification_round()

        while True:
            next_event_in = learner.next_verification_in()
            verification_resceduled = learner.get_verification_rescheduling_event()

            timed_out = await wait_for_any(
                [stop_event, verification_resceduled],
                next_event_in,
            )

            if stop_event.is_set():
                return

            if timed_out:
                break


async def learning_task(stop_event: trio.Event, learner: Learner) -> None:
    while True:
        if learner.is_empty():
            await learner.seed_round(must_succeed=False)
        else:
            await learner.learning_round()

        next_event_in = learner.next_learning_in()

        await wait_for_any([stop_event], next_event_in)
        if stop_event.is_set():
            return


async def staker_query_task(stop_event: trio.Event, learner: Learner) -> None:
    while True:
        await learner.load_staking_providers_and_report()

        await wait_for_any([stop_event], datetime.timedelta(days=1).total_seconds())
        if stop_event.is_set():
            return


@producer
async def verified_nodes_iter(
    yield_: Callable[[VerifiedUrsulaInfo], Awaitable[None]],
    learner: Learner,
    addresses: Iterable[IdentityAddress],
    verified_within: Optional[float] = None,
) -> None:

    if learner.is_empty():
        await learner.seed_round()

    addresses = set(addresses)
    now = learner.clock.utcnow()

    async with trio.open_nursery() as nursery:
        while True:

            new_verified_nodes_event = learner.get_new_verified_nodes_event()
            node_entries = learner.get_verified_node_entries()

            for address in list(addresses):
                node_entry = node_entries.get(address, None)
                if node_entry is None:
                    continue

                if verified_within and node_entry.verified_at < now - datetime.timedelta(
                    seconds=verified_within
                ):
                    nursery.start_soon(learner.verify_contact_and_report, node_entry.node.contact)
                    continue

                addresses.remove(address)
                await yield_(node_entry.node)

            if not addresses:
                break

            for address in addresses:
                possible_contacts = learner.get_possible_contacts_for(address)
                for contact in possible_contacts:
                    nursery.start_soon(learner.verify_contact_and_report, contact)

            # There has been some `awaits`, so new nodes could have been verified
            # If not, force run verification/learning of random nodes
            while not new_verified_nodes_event.is_set():

                new_verified_nodes_event = learner.get_new_verified_nodes_event()

                # TODO: we can run several instances here,
                # learning rounds are supposed to be reentrable
                await learner.verification_round()
                await learner.learning_round()


@producer
async def random_verified_nodes_iter(
    yield_: Callable[[VerifiedUrsulaInfo], Awaitable[None]],
    learner: Learner,
    amount: int,
    overhead: int = 0,
    verified_within: Optional[float] = None,
) -> None:

    if learner.is_empty():
        await learner.seed_round()

    now = learner.clock.utcnow()

    providers = learner.get_available_staking_providers()
    reservoir = WeightedReservoir(providers, lambda entry: entry.weight)

    def is_usable(
        address: IdentityAddress, node_entries: Mapping[IdentityAddress, NodeEntry]
    ) -> bool:
        if drawn_entry.address not in node_entries:
            return False

        if verified_within is None:
            return True

        return now - node_entries[address].verified_at < datetime.timedelta(seconds=verified_within)

    returned = 0
    drawn = 0
    failed = 0

    send_channel, receive_channel = trio.open_memory_channel[Optional[VerifiedUrsulaInfo]](0)

    async def verify_and_yield(drawn_entry: StakingProviderEntry) -> None:
        node = await learner.verify_contact_and_report(drawn_entry.contact)
        await send_channel.send(node)

    async with trio.open_nursery() as nursery:
        while True:

            node_entries = learner.get_verified_node_entries()

            while drawn < amount + failed + overhead and reservoir:
                drawn += 1
                drawn_entry = reservoir.draw()

                if is_usable(drawn_entry.address, node_entries):
                    returned += 1
                    await yield_(node_entries[drawn_entry.address].node)
                    if returned == amount:
                        nursery.cancel_scope.cancel()
                        return
                else:
                    nursery.start_soon(verify_and_yield, drawn_entry)

            node = await receive_channel.receive()
            if node is None:
                failed += 1
            else:
                returned += 1
                await yield_(node)
                if returned == amount:
                    nursery.cancel_scope.cancel()
                    return


async def get_ursulas(
    learner: Learner,
    quantity: int,
    include_ursulas: Iterable[IdentityAddress],
    exclude_ursulas: Iterable[IdentityAddress],
) -> List[VerifiedUrsulaInfo]:
    nodes = []

    async with verified_nodes_iter(learner, include_ursulas, verified_within=60) as node_iter:
        async for node in node_iter:
            nodes.append(node)

    if len(nodes) < quantity:
        overhead = max(1, (quantity - len(nodes)) // 5)
        async with random_verified_nodes_iter(
            learner=learner,
            amount=quantity,
            overhead=overhead,
            verified_within=60,
        ) as node_iter:
            async for node in node_iter:
                nodes.append(node)

    return nodes
