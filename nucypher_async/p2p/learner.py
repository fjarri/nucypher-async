from bisect import bisect_right
from itertools import accumulate
import datetime
import random
from typing import (
    Optional,
    Iterable,
    Tuple,
    List,
    Generic,
    Callable,
    TypeVar,
    Sequence,
    Awaitable,
    Mapping,
)

import trio

from nucypher_core import MetadataRequest

from ..base.peer import PeerError
from ..base.time import BaseClock
from ..drivers.identity import IdentityAddress, AmountT, IdentityClient
from ..drivers.peer import Contact, PeerClient
from ..drivers.time import SystemClock
from ..domain import Domain
from ..storage import InMemoryStorage, BaseStorage
from ..utils import wait_for_any
from ..utils.logging import NULL_LOGGER, Logger
from ..utils.producer import producer
from .ursula import UrsulaInfo, UrsulaClient
from .verification import VerifiedUrsulaInfo, verify_staking_remote, PeerVerificationError
from .fleet_sensor import FleetSensor, NodeEntry, StakingProviderEntry
from .fleet_state import FleetState


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


class Learner:
    """
    The client for P2P network of Ursulas, keeping the metadata of known nodes
    and running the background learning task.
    """

    VERIFICATION_TIMEOUT = 10
    LEARNING_TIMEOUT = 10
    STAKING_PROVIDERS_TIMEOUT = 30

    def __init__(
        self,
        domain: Domain,
        identity_client: IdentityClient,
        this_node: Optional[VerifiedUrsulaInfo] = None,
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

        self._ursula_client = UrsulaClient(peer_client)
        self._identity_client = identity_client

        self.domain = domain

        # Even though we technically don't need it for a passive learner
        # (since we don't have to report out fleet state when doing RPC),
        # we still initialize it for simplicity sake,
        # and in case the user wants to know the fleet state.
        # The only overhead is the dictionary of metadatas
        # (which are instantiated elsewhere anyway),
        # and the checksum is only calculated on demand.
        self.fleet_state = FleetState(self._clock, this_node)

        self._this_node = this_node
        self.fleet_sensor = FleetSensor(self._clock, this_node)

        self._seed_contacts = seed_contacts or []

    def _test_set_seed_contacts(self, seed_contacts: Iterable[Contact]) -> None:
        """
        This function is for tests only.
        Supposed to be called before starting the server.
        """
        self._seed_contacts = list(seed_contacts)

    def _test_add_verified_node(self, node: VerifiedUrsulaInfo, stake: AmountT) -> None:
        """
        This function is for tests only.
        Supposed to be called before starting the server.
        """
        self.fleet_sensor.report_verified_node(node, stake)
        self.fleet_state.add_metadatas([node])

    @producer
    async def verified_nodes_iter(
        self,
        yield_: Callable[[VerifiedUrsulaInfo], Awaitable[None]],
        addresses: Iterable[IdentityAddress],
        verified_within: Optional[float] = None,
    ) -> None:

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
                        nursery.start_soon(self._verify_contact_and_report, node_entry.node.contact)
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

                    # TODO: we can run several instances here,
                    # learning rounds are supposed to be reentrable
                    await self.verification_round()
                    await self.learning_round()

    @producer
    async def random_verified_nodes_iter(
        self,
        yield_: Callable[[VerifiedUrsulaInfo], Awaitable[None]],
        amount: int,
        overhead: int = 0,
        verified_within: Optional[float] = None,
    ) -> None:

        if self.fleet_sensor.is_empty():
            await self.seed_round()

        now = self._clock.utcnow()

        providers = self.fleet_sensor.get_available_staking_providers()
        reservoir = WeightedReservoir(providers, lambda entry: entry.weight)

        def is_usable(
            address: IdentityAddress, node_entries: Mapping[IdentityAddress, NodeEntry]
        ) -> bool:
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

        send_channel, receive_channel = trio.open_memory_channel[Optional[VerifiedUrsulaInfo]](0)

        async def verify_and_yield(drawn_entry: StakingProviderEntry) -> None:
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

    async def _verify_contact(self, contact: Contact) -> Tuple[VerifiedUrsulaInfo, AmountT]:
        self._logger.debug("Verifying a contact {}", contact)

        # TODO: merge all of it into `public_information()`?
        secure_contact = await self._ursula_client.handshake(contact)
        metadata = await self._ursula_client.public_information(secure_contact)
        ursula_info = UrsulaInfo(metadata)

        async with self._identity_client.session() as session:
            staking_provider_address = ursula_info.staking_provider_address
            operator_address = await verify_staking_remote(session, staking_provider_address)
            staked = await session.get_staked_amount(staking_provider_address)

        # TODO: separate stateless checks (can be done once) and transient checks
        # (expiry, staking status etc), and only perform the former if the metadata changed.
        node = VerifiedUrsulaInfo.checked_remote(
            self._clock, ursula_info, secure_contact, operator_address, self.domain
        )

        return node, staked

    async def _learn_from_node(self, node: VerifiedUrsulaInfo) -> List[UrsulaInfo]:
        self._logger.debug(
            "Learning from {} ({})",
            node.contact,
            node.staking_provider_address,
        )

        if self._this_node:
            request = MetadataRequest(self.fleet_state.checksum, [self._this_node.metadata])
            metadata_response = await self._ursula_client.node_metadata_post(
                node.secure_contact, request
            )
        else:
            metadata_response = await self._ursula_client.node_metadata_get(node.secure_contact)

        try:
            payload = metadata_response.verify(node.verifying_key)
        except Exception as exc:  # TODO: can we narrow it down?
            # TODO: should it be a separate error class?
            raise PeerVerificationError("Failed to verify MetadataResponse") from exc

        return [UrsulaInfo(metadata) for metadata in payload.announce_nodes]

    async def _learn_from_node_and_report(self, node: VerifiedUrsulaInfo) -> None:
        with self.fleet_sensor.try_lock_contact_for_learning(node.contact) as (
            contact,
            result,
        ):
            if contact is None:
                await result.wait()
                return

            try:
                with trio.fail_after(self.LEARNING_TIMEOUT):
                    metadatas = await self._learn_from_node(node)
            except (PeerError, trio.TooSlowError) as exc:
                if isinstance(exc, trio.TooSlowError):
                    message = "timed out"
                else:
                    message = str(exc)
                self._logger.debug(
                    "Error when trying to learn from {} ({}): {}",
                    node.contact,
                    node.staking_provider_address.checksum,
                    message,
                )
                self.fleet_sensor.report_bad_contact(node.contact)
                self.fleet_state.remove_contact(node.contact)
            else:
                self._logger.debug(
                    "Learned from {} ({})",
                    node.contact,
                    node.staking_provider_address.checksum,
                )
                self.fleet_sensor.report_active_learning_results(node, metadatas)
                self.fleet_state.add_metadatas(metadatas)
            finally:
                # We just need to signal that the learning ended, no info to return
                result.set(None)

    async def _verify_contact_and_report(self, contact: Contact) -> Optional[VerifiedUrsulaInfo]:
        with self.fleet_sensor.try_lock_contact_for_verification(contact) as (contact_, result):
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
                self.fleet_state.remove_contact(contact)
            else:
                self._logger.debug("Verified {}: {}", contact, node)
                # Assuming here that since the node is verified, `node.contact == contact`
                # (and we won't try to verify `contact` again).
                # Is there a way to enforce it more explicitly?
                self.fleet_sensor.report_verified_node(node, staked_amount)
                self.fleet_state.add_metadatas([node])
            finally:
                result.set(node)

        return node

    # External API

    def metadata_to_announce(self) -> List[VerifiedUrsulaInfo]:
        my_metadata = [self._this_node] if self._this_node else []
        return my_metadata + self.fleet_sensor.verified_metadata()

    def passive_learning(self, sender_host: Optional[str], metadatas: Iterable[UrsulaInfo]) -> None:

        # Unfiltered metadata goes into FleetState for compatibility
        self.fleet_state.add_metadatas(metadatas)
        self._logger.debug("Passive learning from {}", sender_host or "unknown host")
        self.fleet_sensor.report_passive_learning_results(sender_host, metadatas)

    async def load_staking_providers_and_report(self) -> None:
        try:
            with trio.fail_after(self.STAKING_PROVIDERS_TIMEOUT):
                async with self._identity_client.session() as session:
                    providers = await session.get_active_staking_providers()
        except trio.TooSlowError as exc:
            self._logger.debug(f"Failed to get staking providers list from the blockchain: {exc}")
            return

        self.fleet_sensor.report_staking_providers(providers)

    async def seed_round(self, must_succeed: bool = False) -> None:
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

    async def verification_round(
        self, new_contacts_num: int = 10, old_contacts_num: int = 10
    ) -> None:
        self._logger.debug("Starting a verification round")

        new_contacts = self.fleet_sensor.get_contacts_to_verify(new_contacts_num)
        old_contacts = self.fleet_sensor.get_contacts_to_reverify(old_contacts_num)

        async def verify_and_learn(contact: Contact) -> None:
            node = await self._verify_contact_and_report(contact)
            if node:
                await self._learn_from_node_and_report(node)

        async with trio.open_nursery() as nursery:
            for contact in new_contacts:
                nursery.start_soon(verify_and_learn, contact)
            for contact in old_contacts:
                nursery.start_soon(self._verify_contact_and_report, contact)

    async def learning_round(self, nodes_num: int = 1) -> None:
        self._logger.debug("Starting a learning round")

        nodes = self.fleet_sensor.get_nodes_to_learn_from(nodes_num)

        async with trio.open_nursery() as nursery:
            for node in nodes:
                nursery.start_soon(self._learn_from_node_and_report, node)

    async def verification_task(self, stop_event: trio.Event) -> None:
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

    async def learning_task(self, stop_event: trio.Event) -> None:
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

    async def staker_query_task(self, stop_event: trio.Event) -> None:
        while True:
            self._logger.debug("Starting a staker query round")
            await self.load_staking_providers_and_report()

            await wait_for_any([stop_event], datetime.timedelta(days=1).total_seconds())
            if stop_event.is_set():
                return
