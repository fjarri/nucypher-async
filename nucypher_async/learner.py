from functools import wraps, partial
from contextlib import asynccontextmanager
from collections import defaultdict
import random
from typing import Optional

import trio
import maya

from nucypher_core import FleetStateChecksum

from .drivers.eth_client import Address
from .drivers.rest_client import Contact, SSLContact
from .client import NetworkClient
from .p2p.fleet_sensor import FleetSensor
from .p2p.fleet_state import FleetState
from .utils import BackgroundTask
from .utils.logging import NULL_LOGGER
from .ursula import RemoteUrsula


class LearningError(Exception):
    pass


class ConnectionError(LearningError):
    pass


class VerificationError(LearningError):
    pass


def producer(wrapped):
    """
    Trio does not allow yielding from inside open nurseries,
    so this function is used to emulate the functionality of an async generator
    by using a channel.
    """

    @asynccontextmanager
    @wraps(wrapped)
    async def wrapper(*args, **kwargs):
        if "send_channel" in kwargs:
            raise TypeError

        send_channel, receive_channel = trio.open_memory_channel(0)

        async def target():
            async with send_channel:
                await wrapped(*args, **kwargs, send_channel=send_channel)

        async with trio.open_nursery() as nursery:
            async with receive_channel:
                nursery.start_soon(target)
                yield receive_channel
                nursery.cancel_scope.cancel()

    wrapper.raw = wrapped
    return wrapper


class Learner:
    """
    The client for P2P network of Ursulas, keeping the metadata of known nodes
    and running the background learning task.
    """

    def __init__(self, rest_client, eth_client, my_metadata=None, seed_contacts=None, parent_logger=NULL_LOGGER):

        self._logger = parent_logger.get_child('Learner')

        self._rest_client = NetworkClient(rest_client)
        self._eth_client = eth_client

        self._my_metadata = my_metadata

        self._seed_contacts = seed_contacts

        self.fleet_state = FleetState(self._my_metadata)

        my_address = Address(self._my_metadata.payload.staker_address) if my_metadata else None
        self.fleet_sensor = FleetSensor(my_address, seed_contacts=seed_contacts)

    @producer
    async def verified_nodes_iter(self, addresses, send_channel):
        """
        TODO: This is a pretty simple algorithm which will fail sometimes
        when it could have succeeded, and sometimes do more work than needed.
        In the future there are the following considerations we want to address:
        - A given address might be in the process of being verified already,
          then we don't need to enqueue another verification
        - We may not have some addresses even in the unverified list;
          we should have an event for that to have been updated.
        - Nodes can be de-verified; currently we assume that if node is verified, it stays that way.
        """

        addresses = set(addresses)

        # Shortcut in case we already have things verified
        for address in list(addresses):
            node = self.fleet_sensor.try_get_verified_node(address)
            if node is not None:
                addresses.remove(address)
                await send_channel.send(node)

        # Check first, maybe we don't need to do the whole concurrency thing
        if not addresses:
            return

        async with trio.open_nursery() as nursery:
            while addresses:
                if not self.fleet_sensor.addresses_are_known(addresses):

                    # TODO: use a special form of learning round here, without sending out known nodes.
                    # This is called on the client side, clients are not supposed to provide that info.

                    # TODO: we can run several instances here, learning rounds are supposed to be reentrable
                    await self.learning_round()

                for address in addresses:
                    possible_contacts = self.fleet_sensor.try_get_possible_contacts(address)
                    for contact in possible_contacts:
                        nursery.start_soon(self._learn_from_contact_and_update_sensor, contact)

                for address in list(addresses):
                    node = self.fleet_sensor.try_get_verified_node(address)
                    if node is not None:
                        addresses.remove(address)
                        await send_channel.send(node)

                if addresses:
                    await self.fleet_sensor._verified_nodes_updated.wait()

    async def _verify_metadata(self, ssl_contact, metadata):
        # NOTE: assuming this metadata is freshly obtained from the node itself

        # Internal self-verification
        if not metadata.verify():
            raise VerificationError("Failed to verify node metadata")

        payload = metadata.payload

        if payload.host != ssl_contact.contact.host:
            raise VerificationError(
                f"Host mismatch: contact has {ssl_contact.contact.host}, "
                f"but metadata has {payload.host}")

        if payload.port != ssl_contact.contact.port:
            raise VerificationError(
                f"Port mismatch: contact has {ssl_contact.contact.port}, "
                f"but metadata has {payload.port}")

        certificate_bytes = ssl_contact.certificate.to_pem_bytes()
        if payload.certificate_bytes != certificate_bytes:
            raise VerificationError(
                f"Certificate mismatch: contact has {certificate_bytes}, "
                f"but metadata has {payload.certificate_bytes}")

        try:
            address_bytes = payload.derive_operator_address()
        except Exception as e:
            raise VerificationError(f"Failed to derive operator address: {e}") from e

        derived_operator_address = Address(address_bytes)
        staker_address = Address(payload.staker_address)

        bonded_operator_address = await self._eth_client.get_operator_address(staker_address)
        if derived_operator_address != bonded_operator_address:
            raise VerificationError(
                f"Invalid decentralized identity evidence: derived {derived_operator_address}, "
                f"but the bonded address is {bonded_operator_address}")

        if not await self._eth_client.is_staker_authorized(staker_address):
            raise VerificationError("Staker is not authorized")

        return RemoteUrsula(metadata, derived_operator_address)

    def metadata_to_announce(self):
        my_metadata = [self._my_metadata] if self._my_metadata else []
        return my_metadata + self.fleet_sensor.verified_metadata()

    async def _learn_from_contact(self, contact: Contact):
        self._logger.debug("Resolving a contact {}", contact)
        try:
            ssl_contact = await self._rest_client.fetch_certificate(contact)
        # TODO: catch an error where the host in the cert is not the same as the host in the contact
        except OSError:
            raise ConnectionError(f"Failed to fetch the certificate from {contact}")

        try:
            metadata = await self._rest_client.public_information(ssl_contact)
        # TODO: what other errors can be thrown? E.g. if there's a server on the other side,
        # but it doesn't have this endpoint?
        except OSError:
            raise ConnectionError(f"Failed to get metadata from {contact}")

        node = await self._verify_metadata(ssl_contact, metadata)
        metadatas = await self._learn_from_node(node)
        return node, metadatas

    async def _learn_from_node(self, node: RemoteUrsula):
        self._logger.debug("Learning from {}", node)
        ssl_contact = node.ssl_contact
        metadata_response = await self._rest_client.node_metadata_post(
            ssl_contact, self.fleet_state.checksum, self.metadata_to_announce())

        try:
            payload = metadata_response.verify(node.verifying_key)
        except Exception as e: # TODO: can we narrow it down?
            raise VerificationError(f"Failed to verify MetadataResponse: {e}") from e

        # TODO: make use of the returned timestamp?

        return payload.announce_nodes

    async def _learn_from_contact_and_update_sensor(self, contact=None):
        with self.fleet_sensor.try_lock_unchecked_contact(contact=contact) as contact:
            if contact is None:
                return
            try:
                node, metadatas = await self._learn_from_contact(contact)
            except LearningError:
                self.fleet_sensor.remove_contact(contact)

            self.fleet_sensor.add_verified_node(node)
            self.fleet_sensor.add_contacts(metadatas)
            self.fleet_state.update(nodes_to_add=metadatas)
            return contact

    async def _learn_from_node_and_update_sensor(self):
        with self.fleet_sensor.try_lock_verified_node() as node:
            if node is None:
                return
            try:
                metadatas = await self._learn_from_node(node)
            except ConnectionError as e:
                self.fleet_sensor.report_verified_node(node, e)
            except VerificationError:
                # TODO: do we remove it from the fleet state here too? Other nodes don't.
                self.fleet_sensor.remove_verified_node(node)

            self.fleet_sensor.add_contacts(metadatas)
            self.fleet_state.update(nodes_to_add=metadatas)
            return node

    async def learning_round(self):
        self._logger.debug("In the learning round")
        contact = await self._learn_from_contact_and_update_sensor()
        if not contact:
            await self._learn_from_node_and_update_sensor()
        self._logger.debug("Finished the learning round")

    def _add_verified_nodes(self, metadatas):
        for metadata in metadatas:
            if metadata.payload.staker_address != self._my_metadata.payload.staker_address:
                node = RemoteUrsula(metadata, metadata.payload.derive_operator_address())
                self.fleet_sensor.add_verified_node(node)
                self.fleet_state.update(nodes_to_add=[metadata])
