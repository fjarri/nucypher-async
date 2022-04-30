import datetime
from functools import wraps, partial
from contextlib import asynccontextmanager
from collections import defaultdict
import random
from typing import Optional
import random

import arrow
import trio

from nucypher_core import FleetStateChecksum, MetadataRequest

from .drivers.identity import IdentityAddress
from .drivers.peer import Contact, PeerClient
from .drivers.time import SystemClock
from .p2p.fleet_sensor import FleetSensor
from .p2p.fleet_state import FleetState
from .peer_api import PeerError
from .storage import InMemoryStorage
from .utils import BackgroundTask
from .utils.logging import NULL_LOGGER
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


class Learner:
    """
    The client for P2P network of Ursulas, keeping the metadata of known nodes
    and running the background learning task.
    """

    VERIFICATION_TIMEOUT = 10
    LEARNING_TIMEOUT = 10
    STAKING_PROVIDERS_TIMEOUT = 30

    def __init__(self, domain, identity_client, peer_client=None, this_node=None, seed_contacts=None,
            parent_logger=NULL_LOGGER, storage=None, clock=None):

        if peer_client is None:
            peer_client = PeerClient()

        self._clock = clock or SystemClock()
        self._logger = parent_logger.get_child('Learner')

        if storage is None:
            storage = InMemoryStorage()
        self._storage = storage

        self._peer_client = peer_client
        self._identity_client = identity_client

        self.domain = domain

        if this_node:
            my_address = this_node.staking_provider_address
            my_contact = this_node.secure_contact.contact
            my_metadata = this_node.metadata
        else:
            my_address = None
            my_contact = None
            my_metadata = None

        self._my_metadata = my_metadata
        self._my_node = this_node

        self.fleet_state = FleetState(self._clock, my_metadata)
        self.fleet_sensor = FleetSensor(self._clock, my_address, my_contact)
        self._seed_contacts = seed_contacts or []

    def _add_verified_nodes(self, nodes, stakes):
        # TODO: move to tests
        for node, stake in zip(nodes, stakes):
            if node.staking_provider_address != self._my_node.staking_provider_address:
                self.fleet_sensor.report_verified_node(node.secure_contact.contact, node, stake)
                self.fleet_state.add_metadatas([node.metadata])

    @producer
    async def verified_nodes_iter(self, yield_, addresses, verified_within=None):

        if self.fleet_sensor.is_empty():
            await self.seed_round()

        addresses = set(addresses)
        now = self._clock.utcnow()

        async with trio.open_nursery() as nursery:
            while True:

                new_verified_nodes_event = self.fleet_sensor._new_verified_nodes

                for address in list(addresses):
                    node_entry = self.fleet_sensor.verified_node_entries.get(address, None)
                    if node_entry is None:
                        continue

                    if verified_within and node_entry.verified_at < now - datetime.timedelta(seconds=verified_within):
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

                    new_verified_nodes_event = self.fleet_sensor._new_verified_nodes

                    # TODO: we can run several instances here, learning rounds are supposed to be reentrable
                    await self.verification_round()
                    await self.learning_round()

    @producer
    async def random_verified_nodes_iter(self, yield_, amount, overhead=0, exclude=None, verified_within=None):

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

            return now - node_entries[address].verified_at < datetime.timedelta(seconds=verified_within)

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

    async def _verify_contact(self, contact: Contact):
        self._logger.debug("Verifying a contact {}", contact)

        secure_contact = await self._peer_client.handshake(contact)
        peer = await self._peer_client.public_information(secure_contact, self._clock)

        async with self._identity_client.session() as session:
            # TODO: abstraction leak
            staking_provider_address = IdentityAddress(peer.metadata.payload.staking_provider_address)
            operator_address = await verify_staking_remote(session, staking_provider_address)
            staked = await session.get_staked_amount(staking_provider_address)

        node = PublicUrsula.checked_remote(peer, operator_address, self.domain)

        return node, staked

    async def _learn_from_node(self, node: PublicUrsula):
        self._logger.debug(
            "Learning from {} ({})",
            node.secure_contact.contact, node.staking_provider_address)

        if self._my_node:
            request = MetadataRequest(self.fleet_state.checksum, [self._my_metadata])
            metadata_response = await self._peer_client.node_metadata_post(node.secure_contact, request)
        else:
            metadata_response = await self._peer_client.node_metadata_get(node.secure_contact)

        try:
            payload = metadata_response.verify(node.verifying_key)
        except Exception as e: # TODO: can we narrow it down?
            raise NodeVerificationError("Failed to verify MetadataResponse") from e

        return payload.announce_nodes

    async def _learn_from_node_and_report(self, node=None):
        with self.fleet_sensor.try_lock_contact(node.secure_contact.contact) as (contact, result):
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
                    node.secure_contact.contact, node.staking_provider_address.checksum, message)
                self.fleet_sensor.report_bad_contact(node.secure_contact.contact)
                self.fleet_state.remove_contact(node.secure_contact.contact)
            else:
                self._logger.debug(
                    "Learned from {} ({})",
                    node.secure_contact.contact, node.staking_provider_address.checksum)
                self.fleet_sensor.report_active_learning_results(node, metadatas)
                self.fleet_state.add_metadatas(metadatas)
            finally:
                result.set(None)

    async def _verify_contact_and_report(self, contact):
        with self.fleet_sensor.try_lock_contact(contact) as (contact_, result):
            if contact_ is None:
                self._logger.debug("{} is already being verified", contact)
                return await result.wait()

            node = None
            try:
                with trio.fail_after(self.VERIFICATION_TIMEOUT):
                    node, staked_amount = await self._verify_contact(contact)
            except (PeerError, trio.TooSlowError) as e:
                if isinstance(e, trio.TooSlowError):
                    message = "timed out"
                else:
                    message = str(e)
                self._logger.debug("Error when trying to verify {}: {}", contact, message)
                self.fleet_sensor.report_bad_contact(contact)
                self.fleet_state.remove_contact(contact)
            else:
                self._logger.debug("Verified {}: {}", contact, node)
                self.fleet_sensor.report_verified_node(contact, node, staked_amount)
                self.fleet_state.add_metadatas([node.metadata])
            finally:
                result.set(node)

        return node

    # External API

    def metadata_to_announce(self):
        my_metadata = [self._my_metadata] if self._my_metadata else []
        return my_metadata + self.fleet_sensor.verified_metadata()

    def passive_learning(self, sender_host, metadatas):

        # Unfiltered metadata goes into FleetState for compatibility
        self.fleet_state.add_metadatas(metadatas)
        new_contacts_added = self.fleet_sensor.report_passive_learning_results(sender_host, metadatas)

        if new_contacts_added:
            return self.fleet_sensor.next_verification_in()
        else:
            return None

    async def load_staking_providers_and_report(self):
        try:
            with trio.fail_after(self.STAKING_PROVIDERS_TIMEOUT):
                async with self._identity_client.session() as session:
                    providers = await session.get_active_staking_providers()
        except trio.TooSlowError as e:
            self._logger.debug("Failed to get staking providers list from the blockchain: {}", e)
            return

        self.fleet_sensor.report_staking_providers(providers)

    async def seed_round(self):
        if not self._seed_contacts:
            return

        for contact in self._seed_contacts:
            await self._verify_contact_and_report(contact)
            if not self.fleet_sensor.is_empty():
                return

        raise RuntimeError("Failed to learn from the seed nodes")

    async def verification_round(self, new_contacts_num=10, old_contacts_num=10):
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

        return self.fleet_sensor.next_verification_in()

    async def learning_round(self, nodes_num=1):
        nodes = self.fleet_sensor.get_nodes_to_learn_from(nodes_num)

        async with trio.open_nursery() as nursery:
            for node in nodes:
                nursery.start_soon(self._learn_from_node_and_report, node)

        return self.fleet_sensor.next_verification_in(), self.fleet_sensor.next_learning_in()
