import datetime
from collections.abc import Iterable

import trio

from .._drivers.time import SystemClock
from .._utils import wait_for_any
from ..base.time import BaseClock
from ..blockchain.identity import AmountT, IdentityAddress, IdentityClient
from ..domain import Domain
from ..logging import NULL_LOGGER, Logger
from ._errors import PeerError
from ._fleet_sensor import FleetSensor, FleetSensorSnapshot, NodeEntry, StakingProviderEntry
from ._fleet_state import FleetState
from ._keys import Contact, get_alternative_contact
from ._node_client import NodeClient
from ._node_info import NodeInfo
from ._storage import BaseStorage, InMemoryStorage
from ._verification import PeerVerificationError, VerifiedNodeInfo, verify_staking_remote


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
        node_client: NodeClient,
        identity_client: IdentityClient,
        this_node: VerifiedNodeInfo | None = None,
        seed_contacts: Iterable[Contact] | None = None,
        parent_logger: Logger = NULL_LOGGER,
        storage: BaseStorage | None = None,
        clock: BaseClock | None = None,
    ):
        self.clock = clock or SystemClock()
        self._storage = storage or InMemoryStorage()

        self._logger = parent_logger.get_child("Learner")

        self._node_client = node_client
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
        secure_contact = await self._node_client.handshake(contact)
        node_info = await self._node_client.public_information(secure_contact)

        async with self._identity_client.session() as session:
            staking_provider_address = node_info.staking_provider_address
            operator_address = await verify_staking_remote(session, staking_provider_address)
            staked = await session.get_staked_amount(staking_provider_address)

        # TODO: separate stateless checks (can be done once) and transient checks
        # (expiry, staking status etc), and only perform the former if the metadata changed.
        node = VerifiedNodeInfo.checked_remote(
            self.clock, node_info, secure_contact, operator_address, self._domain
        )

        return node, staked

    async def learn_from_node_and_report(self, node: VerifiedNodeInfo) -> None:
        with self._fleet_sensor.try_lock_contact_for_learning(node.contact) as (
            contact,
            result,
        ):
            if contact is None:
                await result.wait()
                return

            self._logger.debug(
                "Learning from {} ({})",
                node.contact,
                node.staking_provider_address,
            )

            try:
                with trio.fail_after(self.LEARNING_TIMEOUT):
                    node_infos = await self._node_client.exchange_node_info(
                        node, self.fleet_state.checksum, self._this_node
                    )
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

                # Filter out this node from the node infos
                if self._this_node is not None:
                    node_infos = [
                        node_info
                        for node_info in node_infos
                        if node_info.staking_provider_address
                        != self._this_node.staking_provider_address
                    ]

                self._fleet_sensor.report_active_learning_results(node, node_infos)
                self.fleet_state.add_metadatas(node_infos)
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
            except (PeerVerificationError, trio.TooSlowError) as exc:
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
                # TODO: Assuming here that since the node is verified, `node.contact == contact`
                # (and we won't try to verify `contact` again).
                # Is there a way to enforce it more explicitly?
                self._fleet_sensor.report_verified_node(node, staked_amount)
                self.fleet_state.add_metadatas([node])
            finally:
                result.set(node)

        return node

    def passive_learning(self, sender_host: str | None, metadatas: Iterable[NodeInfo]) -> None:
        self._logger.debug("Passive learning from {}", sender_host or "unknown host")

        # Unfiltered metadata goes into FleetState for compatibility
        self.fleet_state.add_metadatas(metadatas)

        # TODO: `sender_host` is probably an IP address? The contact host may be a hostname.
        # Need to get an IP from that and use it for the comparison instead.

        # Filter out only the contact(s) with `remote_address`.
        # We're not going to trust all this metadata anyway.
        metadatas = [metadata for metadata in metadatas if metadata.contact.host == sender_host]
        self._fleet_sensor.report_passive_learning_results(metadatas)

    async def _load_staking_providers_and_report(self) -> None:
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

    def _get_verification_rescheduling_event(self) -> trio.Event:
        """
        Returns an event that gets set if new information caused the next verification
        to be rescheduled to an earlier time.

        Note that the event object may be replaced any time a coroutine
        returns execution to the async runtime.
        """
        return self._fleet_sensor.reschedule_verification_event

    def get_new_verified_nodes_event(self) -> trio.Event:
        """
        Returns an event that gets set if a new node is added to the verified nodes list.

        Note that the event object may be replaced any time a coroutine
        returns execution to the async runtime.
        """
        return self._fleet_sensor.new_verified_nodes_event

    def get_possible_contacts_for(self, address: IdentityAddress) -> set[Contact]:
        return self._fleet_sensor.try_get_possible_contacts_for(address)

    def get_available_staking_providers(self) -> list[StakingProviderEntry]:
        return self._fleet_sensor.get_available_staking_providers()

    def get_verified_node_entries(self) -> dict[IdentityAddress, NodeEntry]:
        return self._fleet_sensor.verified_node_entries()

    def get_verified_nodes(self) -> list[VerifiedNodeInfo]:
        return self._fleet_sensor.verified_node_infos()

    def get_snapshot(self) -> FleetSensorSnapshot:
        return self._fleet_sensor.get_snapshot()

    async def verification_task(self, stop_event: trio.Event) -> None:
        while True:
            await self.verification_round()

            while True:
                next_event_in = self._fleet_sensor.next_verification_in()
                verification_resceduled = self._get_verification_rescheduling_event()

                try:
                    with trio.fail_after(next_event_in):
                        await wait_for_any([stop_event, verification_resceduled])
                except trio.TooSlowError:
                    break

                if stop_event.is_set():
                    return

    async def learning_task(self, stop_event: trio.Event) -> None:
        while True:
            if self._fleet_sensor.is_empty():
                await self.seed_round(must_succeed=False)
            else:
                await self.learning_round()

            next_event_in = self._fleet_sensor.next_learning_in()

            with trio.move_on_after(next_event_in):
                await stop_event.wait()

            if stop_event.is_set():
                return

    async def staker_query_task(self, stop_event: trio.Event) -> None:
        while True:
            await self._load_staking_providers_and_report()

            with trio.move_on_after(datetime.timedelta(days=1).total_seconds()):
                await stop_event.wait()

            if stop_event.is_set():
                return
