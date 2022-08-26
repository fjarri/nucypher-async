import datetime
from functools import wraps, partial
from contextlib import asynccontextmanager
from collections import defaultdict
import random
from typing import Optional, Iterable, Tuple, List
import random

import arrow
import trio
from attr import frozen

from nucypher_core import FleetStateChecksum, MetadataRequest, MetadataResponse

from .base.peer import PeerError
from .base.time import BaseClock
from .drivers.identity import IdentityAddress, AmountT, IdentityClient
from .drivers.peer import Contact, PeerClient, PeerVerificationError, PeerInfo
from .drivers.time import SystemClock
from .domain import Domain
from .p2p.fleet_sensor import FleetSensor
from .p2p.fleet_state import FleetState
from .storage import InMemoryStorage, BaseStorage
from .utils import BackgroundTask, wait_for_any
from .utils.logging import NULL_LOGGER, Logger
from .utils.producer import producer
from .verification import PublicUrsula, verify_staking_remote

import random
from bisect import bisect_right
from itertools import accumulate


class WeightedReservoir:
    def __init__(self, elements, get_weight):
        weights = [get_weight(elem) for elem in elements]
        self.totals = list(accumulate(weights))
        self.elements = elements
        self._length = len(elements)

    def draw(self):
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

    def __len__(self):
        return self._length


class _Learner:
    """
    The client for P2P network of Ursulas, keeping the metadata of known nodes
    and running the background learning task.
    """

    VERIFICATION_TIMEOUT = 10
    LEARNING_TIMEOUT = 10
    STAKING_PROVIDERS_TIMEOUT = 30

    def __init__(
        self,
        this_node: Optional[PublicUrsula],
        domain: Domain,
        identity_client: IdentityClient,
        peer_client: Optional[PeerClient] = None,
        seed_contacts: Optional[Iterable[Contact]] = None,
        parent_logger: Logger = NULL_LOGGER,
        storage: Optional[BaseStorage] = None,
        clock: Optional[BaseClock] = None,
    ):

        if peer_client is None:
            peer_client = PeerClient()

        self._clock = clock or SystemClock()
        self._logger = parent_logger.get_child("Learner")

        if storage is None:
            storage = InMemoryStorage()
        self._storage = storage

        self._peer_client = peer_client
        self._identity_client = identity_client

        self.domain = domain

        if this_node:
            my_address = this_node.staking_provider_address
            my_contact = this_node.contact
        else:
            my_address = None
            my_contact = None

        self.fleet_sensor = FleetSensor(self._clock, my_address, my_contact)
        self._seed_contacts = seed_contacts or []

    def _fleet_state_add_metadatas(self, nodes: Iterable[PeerInfo]):
        # Overloaded for active Learner
        pass

    def _add_verified_nodes(self, nodes: Iterable[PublicUrsula], stakes: Iterable[AmountT]):
        for node, stake in zip(nodes, stakes):
            self.fleet_sensor.report_verified_node(node.secure_contact.contact, node, stake)
        self._fleet_state_add_metadatas(nodes)

    @producer
    async def verified_nodes_iter(self, yield_, addresses, verified_within=None):

        if self.fleet_sensor.is_empty():
            await self.seed_round()

        addresses = set(addresses)
        now = self._clock.utcnow()

        async with trio.open_nursery() as nursery:
            while True:

                new_verified_nodes_event = self.fleet_sensor.new_verified_nodes_event

                for address in list(addresses):
                    node_entry = self.fleet_sensor.verified_node_entries.get(address, None)
                    if node_entry is None:
                        continue

                    if verified_within and node_entry.verified_at < now - datetime.timedelta(
                        seconds=verified_within
                    ):
                        nursery.start_soon(self._verify_node_and_report, node_entry.node)
                        continue

                    addresses.remove(address)
                    await yield_(node_entry.node)

                if not addresses:
                    break

                for address in addresses:
                    possible_contacts = self.fleet_sensor.try_get_possible_contacts_for(address)
                    for contact in possible_contacts:
                        nursery.start_soon(self._verify_contact_and_report, contact)

                # There has been some `awaits`, so new nodes could have been verified
                # If not, force run verification/learning of random nodes
                while not new_verified_nodes_event.is_set():

                    new_verified_nodes_event = self.fleet_sensor.new_verified_nodes_event

                    # TODO: we can run several instances here, learning rounds are supposed to be reentrable
                    await self.verification_round()
                    await self.learning_round()

    @producer
    async def random_verified_nodes_iter(
        self, yield_, amount, overhead=0, exclude=None, verified_within=None
    ):

        if self.fleet_sensor.is_empty():
            await self.seed_round()

        now = self._clock.utcnow()

        providers = self.fleet_sensor.get_available_staking_providers(exclude=exclude)
        reservoir = WeightedReservoir(providers, lambda entry: entry.weight)

        def is_usable(address, node_entries):
            if drawn_entry.address not in node_entries:
                return False

            if verified_within is None:
                return True

            return now - node_entries[address].verified_at < datetime.timedelta(
                seconds=verified_within
            )

        returned = 0
        drawn = 0
        failed = 0

        send_channel, receive_channel = trio.open_memory_channel(0)

        async def verify_and_yield(drawn_entry):
            node = await self._verify_contact_and_report(drawn_entry.contact)
            await send_channel.send(node)

        async with trio.open_nursery() as nursery:
            while True:

                node_entries = self.fleet_sensor.verified_node_entries

                while drawn < amount + failed + overhead and reservoir:
                    drawn += 1
                    drawn_entry = reservoir.draw()
                    self._logger.debug("Drawn {}", drawn_entry.address)

                    if is_usable(drawn_entry.address, node_entries):
                        self._logger.debug("{} is instanlty usable", drawn_entry.address)
                        returned += 1
                        await yield_(node_entries[drawn_entry.address].node)
                        if returned == amount:
                            nursery.cancel_scope.cancel()
                            return
                    else:
                        self._logger.debug("Scheduling verification of {}", drawn_entry.address)
                        nursery.start_soon(verify_and_yield, drawn_entry)

                node = await receive_channel.receive()
                if node is None:
                    failed += 1
                else:
                    self._logger.debug("Verified {}, yielding", node.staking_provider_address)
                    returned += 1
                    await yield_(node)
                    if returned == amount:
                        nursery.cancel_scope.cancel()
                        return

    async def _verify_contact(self, contact: Contact) -> Tuple[PublicUrsula, AmountT]:
        self._logger.debug("Verifying a contact {}", contact)

        # TODO: merge all of it into `public_information()`?
        secure_contact = await self._peer_client.handshake(contact)
        metadata = await self._peer_client.public_information(secure_contact)
        peer_info = PeerInfo(metadata)

        async with self._identity_client.session() as session:
            staking_provider_address = peer_info.staking_provider_address
            operator_address = await verify_staking_remote(session, staking_provider_address)
            staked = await session.get_staked_amount(staking_provider_address)

        # TODO: separate stateless checks (can be done once) and transient checks
        # (expiry, staking status etc), and only perform the former if the metadata changed.
        node = PublicUrsula.checked_remote(
            self._clock, peer_info, secure_contact, operator_address, self.domain
        )

        return node, staked

    async def _exchange_metadata(self, node: PublicUrsula) -> MetadataResponse:
        # Overloaded for active Learner
        return await self._peer_client.node_metadata_get(node.secure_contact)

    async def _learn_from_node(self, node: PublicUrsula) -> List[PeerInfo]:
        self._logger.debug(
            "Learning from {} ({})",
            node.secure_contact.contact,
            node.staking_provider_address,
        )

        metadata_response = await self._exchange_metadata(node)

        try:
            payload = metadata_response.verify(node.verifying_key)
        except Exception as exc:  # TODO: can we narrow it down?
            # TODO: should it be a separate error class?
            raise PeerVerificationError("Failed to verify MetadataResponse") from exc

        return [PeerInfo(metadata) for metadata in payload.announce_nodes]

    def _fleet_state_remove_contact(self, contact: Contact):
        # overloaded for active Learner
        pass

    async def _learn_from_node_and_report(self, node: PublicUrsula):
        with self.fleet_sensor.try_lock_contact(node.secure_contact.contact) as (
            contact,
            result,
        ):
            if contact is None:
                return await result.wait()

            try:
                with trio.fail_after(self.LEARNING_TIMEOUT):
                    metadatas = await self._learn_from_node(node)
            except (PeerError, trio.TooSlowError) as e:
                if isinstance(e, trio.TooSlowError):
                    message = "timed out"
                else:
                    message = str(e)
                self._logger.debug(
                    "Error when trying to learn from {} ({}): {}",
                    node.secure_contact.contact,
                    node.staking_provider_address.checksum,
                    message,
                )
                self.fleet_sensor.report_bad_contact(node.secure_contact.contact)
                self._fleet_state_remove_contact(node.secure_contact.contact)
            else:
                self._logger.debug(
                    "Learned from {} ({})",
                    node.secure_contact.contact,
                    node.staking_provider_address.checksum,
                )
                self.fleet_sensor.report_active_learning_results(node, metadatas)
                self._fleet_state_add_metadatas(metadatas)
            finally:
                result.set(None)

    async def _verify_contact_and_report(self, contact: Contact):
        with self.fleet_sensor.try_lock_contact(contact) as (contact_, result):
            if contact_ is None:
                self._logger.debug("{} is already being verified", contact)
                return await result.wait()

            node = None
            try:
                with trio.fail_after(self.VERIFICATION_TIMEOUT):
                    node, staked_amount = await self._verify_contact(contact)
            except (PeerError, trio.TooSlowError) as exc:
                if isinstance(exc, trio.TooSlowError):
                    message = "timed out"
                else:
                    message = str(exc)
                self._logger.debug(
                    "Error when trying to verify {}: {}",
                    contact,
                    message,
                    exc_info=True,
                )
                self.fleet_sensor.report_bad_contact(contact)
                self._fleet_state_remove_contact(contact)
            else:
                self._logger.debug("Verified {}: {}", contact, node)
                self.fleet_sensor.report_verified_node(contact, node, staked_amount)
                self._fleet_state_add_metadatas([node])
            finally:
                result.set(node)

        return node

    # External API

    def _this_node_if_active(self) -> Optional[PublicUrsula]:
        return None

    def metadata_to_announce(self) -> List[PublicUrsula]:
        this_node = self._this_node_if_active()
        my_metadata = [this_node] if this_node else []
        return my_metadata + self.fleet_sensor.verified_metadata()

    def passive_learning(self, sender_host: str, metadatas: Iterable[PeerInfo]):

        # Unfiltered metadata goes into FleetState for compatibility
        self._fleet_state_add_metadatas(metadatas)
        self._logger.debug("Passive learning from {}", sender_host)
        self.fleet_sensor.report_passive_learning_results(sender_host, metadatas)

    async def load_staking_providers_and_report(self):
        try:
            with trio.fail_after(self.STAKING_PROVIDERS_TIMEOUT):
                async with self._identity_client.session() as session:
                    providers = await session.get_active_staking_providers()
        except trio.TooSlowError as e:
            self._logger.debug("Failed to get staking providers list from the blockchain: {}", e)
            return

        self.fleet_sensor.report_staking_providers(providers)

    async def seed_round(self, must_succeed=False):
        self._logger.debug("Starting a seed round")

        if not self._seed_contacts:
            return

        for contact in self._seed_contacts:
            node = await self._verify_contact_and_report(contact)
            if node:
                await self._learn_from_node_and_report(node)
                return

        if must_succeed:
            raise RuntimeError("Failed to learn from the seed nodes")

    async def verification_round(self, new_contacts_num=10, old_contacts_num=10):
        self._logger.debug("Starting a verification round")

        new_contacts = self.fleet_sensor.get_contacts_to_verify(new_contacts_num)
        old_contacts = self.fleet_sensor.get_contacts_to_reverify(old_contacts_num)

        async def verify_and_learn(contact):
            node = await self._verify_contact_and_report(contact)
            if node:
                await self._learn_from_node_and_report(node)

        async with trio.open_nursery() as nursery:
            for contact in new_contacts:
                nursery.start_soon(verify_and_learn, contact)
            for contact in old_contacts:
                nursery.start_soon(self._verify_contact_and_report, contact)

    async def learning_round(self, nodes_num=1):
        self._logger.debug("Starting a learning round")

        nodes = self.fleet_sensor.get_nodes_to_learn_from(nodes_num)

        async with trio.open_nursery() as nursery:
            for node in nodes:
                nursery.start_soon(self._learn_from_node_and_report, node)

    async def verification_task(self, stop_event):
        while True:
            await self.verification_round()

            while True:
                next_event_in = self.fleet_sensor.next_verification_in()
                self._logger.debug("Next verification in: {}", next_event_in)

                timed_out = await wait_for_any(
                    [stop_event, self.fleet_sensor.reschedule_verification_event],
                    next_event_in,
                )

                if stop_event.is_set():
                    return

                if timed_out:
                    break

    async def learning_task(self, stop_event):
        while True:
            if self.fleet_sensor.is_empty():
                await self.seed_round(must_succeed=False)
            else:
                await self.learning_round()

            next_event_in = self.fleet_sensor.next_learning_in()
            self._logger.debug("Next learning in: {}", next_event_in)

            await wait_for_any([stop_event], next_event_in)
            if stop_event.is_set():
                return

    async def staker_query_task(self, stop_event):
        while True:
            self._logger.debug("Starting a staker query round")
            await self.load_staking_providers_and_report()

            await wait_for_any([stop_event], datetime.timedelta(days=1).total_seconds)
            if stop_event.is_set():
                return


class Learner(_Learner):
    """
    A passive (client) Learner.
    """

    def __init__(self, *args, **kwds):
        super().__init__(None, *args, **kwds)


class ActiveLearner(_Learner):
    """
    A Learner acting on behalf of an active peer.
    """

    # The only reason the Learner/ActiveLearner dichotomy exists is FleetState,
    # because we need to expose fleet state checksum in a type-safe manner.
    # FleetSensor does not need this kind of accommodation.

    def __init__(self, this_node: PublicUrsula, *args, **kwds):
        super().__init__(this_node, *args, **kwds)

        # Only need to maintain it for compatibility purposes if we are a peer ourselves.
        self._this_node = this_node
        self.fleet_state = FleetState(self._clock, this_node)

    def _fleet_state_add_metadatas(self, nodes: Iterable[PeerInfo]):
        self.fleet_state.add_metadatas(nodes)

    def _fleet_state_remove_contact(self, contact: Contact):
        self.fleet_state.remove_contact(contact)

    async def _exchange_metadata(self, node: PublicUrsula) -> MetadataResponse:
        request = MetadataRequest(self.fleet_state.checksum, [self._this_node.metadata])
        return await self._peer_client.node_metadata_post(node.secure_contact, request)

    def _this_node_if_active(self) -> Optional[PublicUrsula]:
        return self._this_node
