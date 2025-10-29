from collections.abc import Iterable

import trio
from nucypher_core import Conditions, Context, TreasureMap
from nucypher_core.umbral import Capsule, VerifiedCapsuleFrag

from ..base.peer_error import PeerError
from ..base.time import BaseClock
from ..characters.pre import DelegatorCard, RecipientCard
from ..domain import Domain
from ..drivers.identity import AmountT, IdentityAddress, IdentityClient
from ..drivers.peer import Contact, PeerClient, get_alternative_contact
from ..drivers.time import SystemClock
from ..storage import BaseStorage, InMemoryStorage
from ..utils.logging import NULL_LOGGER, Logger
from .fleet_sensor import FleetSensor, FleetSensorSnapshot, NodeEntry, StakingProviderEntry
from .fleet_state import FleetState
from .node_info import NodeInfo, UrsulaClient
from .verification import VerifiedNodeInfo, verify_staking_remote


class Learner:
    """
    The client for P2P network of nodes, keeping the metadata of known nodes
    and running the background learning task.
    """

    VERIFICATION_TIMEOUT = 10
    LEARNING_TIMEOUT = 10
    STAKING_PROVIDERS_TIMEOUT = 30

    def __init__(
        self,
        domain: Domain,
        identity_client: IdentityClient,
        this_node: VerifiedNodeInfo | None = None,
        peer_client: PeerClient | None = None,
        seed_contacts: Iterable[Contact] | None = None,
        parent_logger: Logger = NULL_LOGGER,
        storage: BaseStorage | None = None,
        clock: BaseClock | None = None,
    ):
        if peer_client is None:
            peer_client = PeerClient()

        self.clock = clock or SystemClock()

        self._logger = parent_logger.get_child("Learner")

        if storage is None:
            storage = InMemoryStorage()
        self._storage = storage

        self._ursula_client = UrsulaClient(peer_client)
        self._identity_client = identity_client

        self._domain = domain

        # Even though we technically don't need it for a passive learner
        # (since we don't have to report out fleet state when doing RPC),
        # we still initialize it for simplicity sake,
        # and in case the user wants to know the fleet state.
        # The only overhead is the dictionary of metadatas
        # (which are instantiated elsewhere anyway),
        # and the checksum is only calculated on demand.
        self.fleet_state = FleetState(self.clock, this_node)

        self._this_node = this_node
        self._fleet_sensor = FleetSensor(self.clock, this_node)

        self._seed_contacts = seed_contacts or []

    def _test_set_seed_contacts(self, seed_contacts: Iterable[Contact]) -> None:
        """
        For tests only.
        Supposed to be called before starting the server.
        """
        self._seed_contacts = list(seed_contacts)

    def _test_add_verified_node(self, node: VerifiedNodeInfo, stake: AmountT) -> None:
        """
        For tests only.
        Supposed to be called before starting the server.
        """
        self._fleet_sensor.report_verified_node(node, stake)
        self.fleet_state.add_metadatas([node])

    async def _verify_contact(self, contact: Contact) -> tuple[VerifiedNodeInfo, AmountT]:
        self._logger.debug("Verifying a contact {}", contact)

        # TODO: merge all of it into `public_information()`?
        secure_contact = await self._ursula_client.handshake(contact)
        ursula_info = await self._ursula_client.public_information(secure_contact)

        async with self._identity_client.session() as session:
            staking_provider_address = ursula_info.staking_provider_address
            operator_address = await verify_staking_remote(session, staking_provider_address)
            staked = await session.get_staked_amount(staking_provider_address)

        # TODO: separate stateless checks (can be done once) and transient checks
        # (expiry, staking status etc), and only perform the former if the metadata changed.
        node = VerifiedNodeInfo.checked_remote(
            self.clock, ursula_info, secure_contact, operator_address, self._domain
        )

        return node, staked

    async def _learn_from_node(self, node: VerifiedNodeInfo) -> list[NodeInfo]:
        self._logger.debug(
            "Learning from {} ({})",
            node.contact,
            node.staking_provider_address,
        )

        if self._this_node:
            ursulas_info = await self._ursula_client.exchange_ursulas_info(
                node, self.fleet_state.checksum, self._this_node
            )
        else:
            ursulas_info = await self._ursula_client.get_ursulas_info(node)

        return ursulas_info

    async def learn_from_node_and_report(self, node: VerifiedNodeInfo) -> None:
        with self._fleet_sensor.try_lock_contact_for_learning(node.contact) as (
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
                message = "timed out" if isinstance(exc, trio.TooSlowError) else str(exc)
                self._logger.error(
                    "Error when trying to learn from {} ({}): {}",
                    node.contact,
                    node.staking_provider_address.checksum,
                    message,
                )
                self._fleet_sensor.report_bad_contact(node.contact)
                self.fleet_state.remove_contact(node.contact)
            else:
                self._logger.debug(
                    "Learned from {} ({})",
                    node.contact,
                    node.staking_provider_address.checksum,
                )
                self._fleet_sensor.report_active_learning_results(node, metadatas)
                self.fleet_state.add_metadatas(metadatas)
            finally:
                # We just need to signal that the learning ended, no info to return
                result.set(None)

    async def verify_contact_and_report(self, contact: Contact) -> VerifiedNodeInfo | None:
        with self._fleet_sensor.try_lock_contact_for_verification(contact) as (
            contact_,
            result,
        ):
            if contact_ is None:
                self._logger.debug("{} is already being verified", contact)
                return await result.wait()

            node = None
            try:
                with trio.fail_after(self.VERIFICATION_TIMEOUT):
                    node, staked_amount = await self._verify_contact(contact)
            except (PeerError, trio.TooSlowError) as exc:
                message = "timed out" if isinstance(exc, trio.TooSlowError) else str(exc)
                self._logger.error(
                    "Error when trying to verify {}: {}",
                    contact,
                    message,
                )
                self._fleet_sensor.report_bad_contact(contact)
                self.fleet_state.remove_contact(contact)
            else:
                self._logger.debug("Verified {}: {}", contact, node)
                # Assuming here that since the node is verified, `node.contact == contact`
                # (and we won't try to verify `contact` again).
                # Is there a way to enforce it more explicitly?
                self._fleet_sensor.report_verified_node(node, staked_amount)
                self.fleet_state.add_metadatas([node])
            finally:
                result.set(node)

        return node

    def passive_learning(self, sender_host: str | None, metadatas: Iterable[NodeInfo]) -> None:
        # Unfiltered metadata goes into FleetState for compatibility
        self.fleet_state.add_metadatas(metadatas)
        self._logger.debug("Passive learning from {}", sender_host or "unknown host")
        self._fleet_sensor.report_passive_learning_results(sender_host, metadatas)

    async def load_staking_providers_and_report(self) -> None:
        try:
            with trio.fail_after(self.STAKING_PROVIDERS_TIMEOUT):
                async with self._identity_client.session() as session:
                    providers = await session.get_active_staking_providers()
        except trio.TooSlowError as exc:
            self._logger.debug(
                "Failed to get staking providers list from the blockchain: {exc}", exc=exc
            )
            return

        self._fleet_sensor.report_staking_providers(providers)

    async def seed_round(self, *, must_succeed: bool = False) -> None:
        self._logger.debug("Starting a seed round")

        if not self._seed_contacts:
            return

        for contact in self._seed_contacts:
            node = await self.verify_contact_and_report(contact)
            if node:
                await self.learn_from_node_and_report(node)
                return

            # A seed node contact can be provided with a domain name,
            # but its certificate is issued for an IP, so the call above will fail.
            alt_contact = await get_alternative_contact(contact)
            if alt_contact is None:
                continue
            node = await self.verify_contact_and_report(alt_contact)
            if node:
                await self.learn_from_node_and_report(node)
                return

        if must_succeed:
            raise RuntimeError("Failed to learn from the seed nodes")

    async def verification_round(
        self, new_contacts_num: int = 10, old_contacts_num: int = 10
    ) -> None:
        self._logger.debug("Starting a verification round")

        new_contacts = self._fleet_sensor.get_contacts_to_verify(new_contacts_num)
        old_contacts = self._fleet_sensor.get_contacts_to_reverify(old_contacts_num)

        async def verify_and_learn(contact: Contact) -> None:
            node = await self.verify_contact_and_report(contact)
            if node:
                await self.learn_from_node_and_report(node)

        async with trio.open_nursery() as nursery:
            for contact in new_contacts:
                nursery.start_soon(verify_and_learn, contact)
            for contact in old_contacts:
                nursery.start_soon(self.verify_contact_and_report, contact)

    async def learning_round(self, nodes_num: int = 1) -> None:
        self._logger.debug("Starting a learning round")

        nodes = self._fleet_sensor.get_nodes_to_learn_from(nodes_num)

        async with trio.open_nursery() as nursery:
            for node in nodes:
                nursery.start_soon(self.learn_from_node_and_report, node)

    async def reencrypt(
        self,
        ursula: VerifiedNodeInfo,
        capsules: list[Capsule],
        treasure_map: TreasureMap,
        delegator_card: DelegatorCard,
        recipient_card: RecipientCard,
        conditions: Conditions | None = None,
        context: Context | None = None,
    ) -> list[VerifiedCapsuleFrag]:
        return await self._ursula_client.reencrypt(
            ursula=ursula,
            capsules=capsules,
            treasure_map=treasure_map,
            delegator_card=delegator_card,
            recipient_card=recipient_card,
            conditions=conditions,
            context=context,
        )

    def next_verification_in(self) -> float:
        return self._fleet_sensor.next_verification_in()

    def get_verification_rescheduling_event(self) -> trio.Event:
        """
        Returns an event that gets set if new information caused the next verification
        to be rescheduled to an earlier time.

        Note that the event object may be replaced any time a coroutine
        returns execution to the async runtime.
        """
        return self._fleet_sensor.reschedule_verification_event

    def next_learning_in(self) -> float:
        return self._fleet_sensor.next_learning_in()

    def get_new_verified_nodes_event(self) -> trio.Event:
        """
        Returns an event that gets set if a new node is added to the verified nodes list.

        Note that the event object may be replaced any time a coroutine
        returns execution to the async runtime.
        """
        return self._fleet_sensor.new_verified_nodes_event

    def is_empty(self) -> bool:
        # TODO: we can hide this method and `seed_round()`, and call them
        # in `learning_round()` instead, to simplify the API.
        return self._fleet_sensor.is_empty()

    def get_possible_contacts_for(self, address: IdentityAddress) -> set[Contact]:
        return self._fleet_sensor.try_get_possible_contacts_for(address)

    def get_available_staking_providers(self) -> list[StakingProviderEntry]:
        return self._fleet_sensor.get_available_staking_providers()

    def get_verified_node_entries(self) -> dict[IdentityAddress, NodeEntry]:
        return self._fleet_sensor.verified_node_entries

    def get_verified_ursulas(self, *, include_this_node: bool = False) -> list[VerifiedNodeInfo]:
        my_metadata = [self._this_node] if include_this_node and self._this_node else []
        return my_metadata + self._fleet_sensor.verified_metadata()

    def get_snapshot(self) -> FleetSensorSnapshot:
        return self._fleet_sensor.get_snapshot()
