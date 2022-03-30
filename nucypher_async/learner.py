import datetime
from functools import wraps, partial
from contextlib import asynccontextmanager
from collections import defaultdict
import random
from typing import Optional

import arrow
import trio

from nucypher_core import FleetStateChecksum

from .drivers.identity import IdentityAddress
from .drivers.rest_client import Contact, SSLContact, HTTPError, ConnectionError, RESTClient
from .drivers.ssl import SSLCertificate
from .drivers.time import Clock
from .client import NetworkClient
from .p2p.fleet_sensor import FleetSensor
from .p2p.fleet_state import FleetState
from .storage import InMemoryStorage
from .utils import BackgroundTask
from .utils.logging import NULL_LOGGER
from .utils.producer import producer
from .ursula import RemoteUrsula


class NodeVerificationError(Exception):
    pass


def verify_metadata_shared(clock, metadata, contact, domain):
    if not metadata.verify():
        raise NodeVerificationError("Metadata self-verification failed")

    payload = metadata.payload

    try:
        certificate = SSLCertificate.from_der_bytes(payload.certificate_der)
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

    now = clock.utcnow()
    if arrow.get(certificate.not_valid_before) > now:
        raise NodeVerificationError(
            f"Certificate is only valid after {certificate.not_valid_before}")
    if arrow.get(certificate.not_valid_after) < now:
        raise NodeVerificationError(
            f"Certificate is only valid until {certificate.not_valid_after}")

    try:
        address_bytes = payload.derive_operator_address()
    except Exception as e:
        raise NodeVerificationError(f"Failed to derive operator address: {e}") from e

    return IdentityAddress(address_bytes)


class Learner:
    """
    The client for P2P network of Ursulas, keeping the metadata of known nodes
    and running the background learning task.
    """

    VERIFICATION_TIMEOUT = 10
    LEARNING_TIMEOUT = 10

    def __init__(self, identity_client, rest_client=None, my_metadata=None, seed_contacts=None,
            parent_logger=NULL_LOGGER, storage=None, domain="mainnet", clock=None):

        if rest_client is None:
            rest_client = RESTClient()

        self._clock = clock or Clock()
        self._logger = parent_logger.get_child('Learner')

        if storage is None:
            storage = InMemoryStorage()
        self._storage = storage

        self._rest_client = NetworkClient(rest_client)
        self._identity_client = identity_client

        self._my_metadata = my_metadata

        self.domain = domain
        self.fleet_state = FleetState(self._clock, self._my_metadata)

        if my_metadata:
            payload = my_metadata.payload
            my_address = IdentityAddress(payload.staking_provider_address)
            my_contact = Contact(payload.host, payload.port)
        else:
            my_address = None
            my_contact = None
        self.fleet_sensor = FleetSensor(self._clock, my_address, my_contact, seed_contacts=seed_contacts)

    def _add_verified_nodes(self, metadatas):
        for metadata in metadatas:
            if metadata.payload.staking_provider_address != self._my_metadata.payload.staking_provider_address:
                node = RemoteUrsula(metadata, metadata.payload.derive_operator_address())
                self.fleet_sensor.report_verified_node(node)
                self.fleet_state.add_metadatas([metadata])

    @producer
    async def verified_nodes_iter(self, yield_, addresses):

        addresses = set(addresses)

        # Shortcut in case we already have things verified
        for address in list(addresses):
            node = self.fleet_sensor.try_get_verified_node(address)
            if node is not None:
                addresses.remove(address)
                await yield_(node)

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
                        await yield_(node)

                if addresses:
                    await self.fleet_sensor._verified_nodes_updated.wait()

    @producer
    async def random_verified_nodes_iter(self, yield_, amount):

        # TODO: add a shortcut in case there's already enough verified nodes
        import random

        returned_addresses = set()
        async with trio.open_nursery() as nursery:
            while len(returned_addresses) < amount:
                all_addresses = self.fleet_sensor._verified_nodes.keys() - returned_addresses
                if len(all_addresses) > 0:
                    address = random.choice(list(all_addresses))
                    returned_addresses.add(address)
                    await yield_(self.fleet_sensor._verified_nodes[address])
                else:
                    event = self.fleet_sensor._verified_nodes_updated
                    while not event.is_set():
                        await self.learning_round()

    async def _verify_metadata(self, ssl_contact, metadata):
        # NOTE: assuming this metadata is freshly obtained from the node itself

        payload = metadata.payload

        certificate_der = ssl_contact.certificate.to_der_bytes()
        if payload.certificate_der != certificate_der:
            raise NodeVerificationError(
                f"Certificate mismatch: contact has {certificate_der}, "
                f"but metadata has {payload.certificate_der}")

        derived_operator_address = verify_metadata_shared(self._clock, metadata, ssl_contact.contact, self.domain)
        staking_provider_address = IdentityAddress(payload.staking_provider_address)

        bonded_operator_address = await self._identity_client.get_operator_address(staking_provider_address)
        if derived_operator_address != bonded_operator_address:
            raise NodeVerificationError(
                f"Invalid decentralized identity evidence: derived {derived_operator_address}, "
                f"but the bonded address is {bonded_operator_address}")

        if not await self._identity_client.is_staking_provider_authorized(staking_provider_address):
            raise NodeVerificationError("Staking provider is not authorized")

        # TODO: is_operator_confirmed()

        return RemoteUrsula(metadata, derived_operator_address)

    async def _verify_contact(self, contact: Contact):
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
        return node

    async def _learn_from_node(self, node: RemoteUrsula):
        self._logger.debug(
            "Learning from {} ({})",
            node.ssl_contact.contact, node.staking_provider_address)

        metadata_to_announce = [self._my_metadata] if self._my_metadata else []

        metadata_response = await self._rest_client.node_metadata_post(
            node.ssl_contact, self.fleet_state.checksum, metadata_to_announce)

        try:
            payload = metadata_response.verify(node.verifying_key)
        except Exception as e: # TODO: can we narrow it down?
            raise NodeVerificationError("Failed to verify MetadataResponse") from e

        return payload.announce_nodes

    async def _learn_from_node_and_report(self, node=None):
        with self.fleet_sensor.try_lock_node_to_learn_from(node) as node:
            if node is None:
                return
            try:
                with trio.fail_after(self.LEARNING_TIMEOUT):
                    metadatas = await self._learn_from_node(node)
            except (OSError, ConnectionError, trio.TooSlowError, NodeVerificationError) as e:
                self._logger.debug(
                    "Failed to learn from {} ({}): {}",
                    node.ssl_contact.contact, node.staking_provider_address, e)
                self.fleet_sensor.report_bad_contact(node.ssl_contact.contact)
                return

            self._logger.debug("Learned from {}: {}", node.ssl_contact.contact, node)
            self.fleet_sensor.report_active_learning_results(node, metadatas)
            self.fleet_state.add_metadatas(metadatas)

    async def _verify_contact_and_report(self):
        with self.fleet_sensor.try_lock_contact_to_verify() as contact:
            if contact is None:
                return
            try:
                with trio.fail_after(self.VERIFICATION_TIMEOUT):
                    node = await self._verify_contact(contact)
            except (HTTPError, ConnectionError, NodeVerificationError, trio.TooSlowError) as e:
                self._logger.debug("Error when trying to learn from {}: {}", contact, e)
                self.fleet_sensor.report_bad_contact(contact)
                return

            self._logger.debug("Verified {}: {}", contact, node)
            self.fleet_sensor.report_verified_node(node)

        await self._learn_from_node_and_report(node)

    async def _verify_node_and_report(self):
        with self.fleet_sensor.try_lock_node_to_verify() as node:
            if node is None:
                return
            try:
                with trio.fail_after(self.VERIFICATION_TIMEOUT):
                    new_node = await self._verify_contact(node.ssl_contact.contact)
            except (HTTPError, ConnectionError, NodeVerificationError, trio.TooSlowError) as e:
                self._logger.debug("Error when trying to learn from {}: {}", node, e)
                self.fleet_sensor.report_bad_node(node)
                self.fleet_state.remove_metadata(node.metadata)
                return

            self._logger.debug("Re-verified {}: {}", node.ssl_contact.contact, node)
            self.fleet_sensor.report_reverified_node(node, new_node)
            self.fleet_state.replace_metadata(node, new_node)

        await self._learn_from_node_and_report(new_node)

    # External API

    def metadata_to_announce(self):
        my_metadata = [self._my_metadata] if self._my_metadata else []
        return my_metadata + self.fleet_sensor.verified_metadata()

    def add_metadatas(self, sender_host, metadatas):

        # Unfiltered metadata goes into FleetState for compatibility
        self.fleet_state.add_metadatas(metadatas)
        self.fleet_sensor.report_passive_learning_results(sender_host, metadatas)

        return self.fleet_sensor.next_verification_in()

    async def verification_round(self):

        # How many events to schedule simultaneusly
        # TODO: this is a learning parameter
        contacts_num = 1
        nodes_num = 1

        # how long to wait until scheduling another round, even if there are already events available
        # TODO: this is a learning parameter
        min_time_between_rounds = 5

        async with trio.open_nursery() as nursery:
            for _ in range(contacts_num):
                nursery.start_soon(self._verify_contact_and_report)
            for _ in range(nodes_num):
                nursery.start_soon(self._verify_node_and_report)

        return self.fleet_sensor.next_verification_in()

    async def learning_round(self):
        # TODO: this is a learning parameter
        # May be adjusted dynamically based on the network state
        learning_timeout = datetime.timedelta(seconds=90)
        await self._learn_from_node_and_report()
        return self.fleet_sensor.next_verification_in(), learning_timeout
