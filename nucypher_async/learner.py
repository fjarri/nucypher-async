import datetime
from functools import wraps, partial
from contextlib import asynccontextmanager
from collections import defaultdict
import random
from typing import Optional

import trio
import maya

from nucypher_core import FleetStateChecksum

from .drivers.eth_client import Address
from .drivers.rest_client import Contact, SSLContact, HTTPError, ConnectionError
from .drivers.ssl import SSLCertificate
from .client import NetworkClient
from .p2p.fleet_sensor import FleetSensor
from .p2p.fleet_state import FleetState
from .storage import InMemoryStorage
from .utils import BackgroundTask
from .utils.logging import NULL_LOGGER
from .ursula import RemoteUrsula


class NodeVerificationError(Exception):
    pass


def verify_metadata_shared(metadata, contact, domain):
    if not metadata.verify():
        raise NodeVerificationError("Metadata self-verification failed")

    payload = metadata.payload

    try:
        certificate = SSLCertificate.from_pem_bytes(payload.certificate_bytes)
    except Exception as e:
        raise NodeVerificationError(f"Invalid certificate bytes in the payload: {e}") from e

    try:
        certificate.verify()
    except ssl.InvalidSignature as e:
        raise NodeVerificationError(f"Invalid certificate signature") from e

    if certificate.declared_host != payload.host:
        raise NodeVerificationError(
            f"Host mismatch: {payload.host} in the metadata, "
            f"{certificate.declared_host} in the certificate")

    if payload.host != contact.host:
        raise NodeVerificationError(
            f"Host mismatch: expected {contact.host}, "
            f"{payload.host} in the metadata")

    if payload.port != contact.port:
        raise NodeVerificationError(
            f"Port mismatch: expected {contact.port}, "
            f"{payload.port} in the metadata")

    if payload.domain != domain:
        raise NodeVerificationError(
            f"Domain mismatch: expected {domain}, "
            f"{payload.domain} in the metadata")

    now = datetime.datetime.utcnow()
    if certificate.not_valid_before > now:
        raise NodeVerificationError(
            f"Certificate is only valid after {certificate.not_valid_before}")
    if certificate.not_valid_after < now:
        raise NodeVerificationError(
            f"Certificate is only valid until {certificate.not_valid_after}")

    try:
        address_bytes = payload.derive_operator_address()
    except Exception as e:
        raise NodeVerificationError(f"Failed to derive operator address: {e}") from e

    return Address(address_bytes)


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

    CONTACT_LEARNING_TIMEOUT = 10
    NODE_LEARNING_TIMEOUT = 10

    def __init__(self, rest_client, eth_client, my_metadata=None, seed_contacts=None,
            parent_logger=NULL_LOGGER, storage=None, domain="mainnet"):

        self._logger = parent_logger.get_child('Learner')

        if storage is None:
            storage = InMemoryStorage()
        self._storage = storage

        self._rest_client = NetworkClient(rest_client)
        self._eth_client = eth_client

        self._my_metadata = my_metadata

        self._seed_contacts = seed_contacts

        self.domain = domain
        self.fleet_state = FleetState(self._my_metadata)

        my_address = Address(self._my_metadata.payload.staker_address) if my_metadata else None
        self.fleet_sensor = FleetSensor(my_address, seed_contacts=seed_contacts)

    @producer
    async def verified_nodes_iter(self, addresses, send_channel):

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

        payload = metadata.payload

        certificate_bytes = ssl_contact.certificate.to_pem_bytes()
        if payload.certificate_bytes != certificate_bytes:
            raise NodeVerificationError(
                f"Certificate mismatch: contact has {certificate_bytes}, "
                f"but metadata has {payload.certificate_bytes}")

        derived_operator_address = verify_metadata_shared(metadata, ssl_contact.contact, self.domain)
        staker_address = Address(payload.staker_address)

        bonded_operator_address = await self._eth_client.get_operator_address(staker_address)
        if derived_operator_address != bonded_operator_address:
            raise NodeVerificationError(
                f"Invalid decentralized identity evidence: derived {derived_operator_address}, "
                f"but the bonded address is {bonded_operator_address}")

        if not await self._eth_client.is_staker_authorized(staker_address):
            raise NodeVerificationError("Staker is not authorized")

        # TODO: is_operator_confirmed()

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
            raise NodeVerificationError(f"Failed to verify MetadataResponse: {e}") from e

        # TODO: make use of the returned timestamp?

        return payload.announce_nodes

    async def _learn_from_contact_and_update_sensor(self, contact=None):
        with self.fleet_sensor.try_lock_unchecked_contact(contact=contact) as contact:
            if contact is None:
                return
            try:
                with trio.fail_after(self.CONTACT_LEARNING_TIMEOUT):
                    node, metadatas = await self._learn_from_contact(contact)
            except (HTTPError, ConnectionError, NodeVerificationError, trio.TooSlowError) as e:
                self._logger.debug("Error when trying to learn from {}: {}", contact, e)
            else:
                self.fleet_sensor.add_verified_node(node)
                self.fleet_sensor.add_contacts(metadatas)
                self.fleet_state.add_metadatas(metadatas)
                return contact
            finally:
                self.fleet_sensor.remove_contact(contact)

    async def _learn_from_node_and_update_sensor(self):
        with self.fleet_sensor.try_lock_verified_node() as node:
            if node is None:
                return
            try:
                with trio.fail_after(self.NODE_LEARNING_TIMEOUT):
                    metadatas = await self._learn_from_node(node)
            except (HTTPError, ConnectionError, NodeVerificationError, trio.TooSlowError) as e:
                self._logger.debug("Error when trying to learn from {}: {}", node, e)
                self.fleet_sensor.remove_verified_node(node)
                self.fleet_state.remove_metadata(node.metadata)
            else:
                self.fleet_sensor.add_contacts(metadatas)
                self.fleet_state.add_metadatas(metadatas)
                return node

    async def learning_round(self):
        self._logger.debug("In the learning round")
        contact = await self._learn_from_contact_and_update_sensor()
        # TODO: if learning from the contact failed, we get None here as well.
        # Need to distinguish between cases when there were no contacts to learn from
        # and a failed learning.
        if not contact:
            await self._learn_from_node_and_update_sensor()
        self._logger.debug("Finished the learning round")

    def _add_verified_nodes(self, metadatas):
        for metadata in metadatas:
            if metadata.payload.staker_address != self._my_metadata.payload.staker_address:
                node = RemoteUrsula(metadata, metadata.payload.derive_operator_address())
                self.fleet_sensor.add_verified_node(node)
                self.fleet_state.add_metadatas([metadata])
