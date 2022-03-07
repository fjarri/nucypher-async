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
from .utils import BackgroundTask
from .utils.logging import NULL_LOGGER
from .ursula import RemoteUrsula


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


def metadata_is_consistent(metadata1, metadata2):
    """
    Checks if two metadata objects could be produced by the same law-abiding node.
    Some elements of the metadata can change over time, e.g. the host/port,
    or the certificate.
    """
    fields = ['staker_address', 'domain', 'verifying_key', 'encrypting_key']
    return all(getattr(metadata1.payload, field) == getattr(metadata2.payload, field) for field in fields)


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

        # unverified contacts: node adrress -> NodeMetadata
        self._unverified_nodes = {}

        # verified contacts: node adrress -> RemoteUrsula
        self._verified_nodes = {}

        self._verified_nodes_updated = trio.Event()

        self.fleet_state_checksum = FleetStateChecksum(this_node=self._my_metadata, other_nodes=[]) # TODO
        self.fleet_state_timestamp = maya.now()

    def add_metadata(self, metadata_list):
        """
        TODO:
        - handle the cases of same host/port, but otherwise different metadata coming from differnt nodes
        - maybe should also record where we got the info from, so we could flag the node for lying to us
        - should we keep the whole metadata at all if we'll request it again as a part of verification?
        """
        for metadata in metadata_list:
            if not self._my_metadata or metadata.payload.staker_address != self._my_metadata.payload.staker_address:
                staker_address = Address(metadata.payload.staker_address)
                self._logger.debug('Recording metadata for {}', staker_address)
                self._unverified_nodes[staker_address] = metadata

    def _add_verified_nodes(self, metadata_list):
        for metadata in metadata_list:
            operator_address = Address(metadata.payload.derive_operator_address())
            node = RemoteUrsula(metadata, operator_address)
            self._verified_nodes[node.staker_address] = node

        # TODO: should it set off the event too? And update the fleet state?

    def verified_nodes(self):
        return self._verified_nodes

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
            if address in self._verified_nodes:
                addresses.remove(address)
                await send_channel.send(self._verified_nodes[address])

        # Check first, maybe we don't need to do the whole concurrency thing
        if not addresses:
            return

        async with trio.open_nursery() as nursery:

            while addresses - self._unverified_nodes.keys() - self._verified_nodes.keys():
                # TODO: use a special form of learning round here, without sending out known nodes.
                # This is called on the client side, clients are not supposed to provide that info.
                self._logger.debug("Scheduling a learning round")
                await self.learning_round()

            for address in addresses:
                if address in self._unverified_nodes:
                    self._logger.debug("Scheduling a verification for {}", address)
                    nursery.start_soon(self._verify_metadata, self._unverified_nodes[address])

            while addresses:
                await self._verified_nodes_updated.wait()
                for address in list(addresses):
                    if address in self._verified_nodes:
                        addresses.remove(address)
                        await send_channel.send(self._verified_nodes[address])

    async def _verify_metadata(self, metadata):
        # NOTE: assuming this metadata is freshly obtained from the node itself

        # TODO: check that the address in the metadata and in the certificate matches
        # the address we got the metadata from.

        # Internal self-verification
        assert metadata.verify()

        derived_operator_address = Address(metadata.payload.derive_operator_address())

        staker_address = Address(metadata.payload.staker_address)
        bonded_operator_address = await self._eth_client.get_operator_address(staker_address)
        if derived_operator_address != bonded_operator_address:
            raise RuntimeError("Invalid decentralized identity evidence")

        if not await self._eth_client.is_staker_authorized(staker_address):
            raise RuntimeError("Staker is not authorized")

        node = RemoteUrsula(metadata, derived_operator_address)

        self._verified_nodes[node.staker_address] = node

        self.fleet_state_timestamp = maya.now()

        # Release whoever was waiting for the state to be updated
        # TODO: only do so if there was a change in the state.
        self._verified_nodes_updated.set()
        await trio.sleep(0) # TODO: is it necessary?
        self._verified_nodes_updated = trio.Event()

        return node

    def metadata_to_announce(self):
        my_metadata = [self._my_metadata] if self._my_metadata else []
        return my_metadata + [node.metadata for node in self._verified_nodes.values()]

    async def _learn_from_contact(self, contact: Contact):
        self._logger.debug("Resolving a contact {}", contact)
        ssl_contact = await self._rest_client.fetch_certificate(contact)
        metadata = await self._rest_client.public_information(ssl_contact)
        assert metadata.payload.host == ssl_contact.contact.host
        assert metadata.payload.port == ssl_contact.contact.port
        node = await self._verify_metadata(metadata)
        return await self._learn_from_node(node)

    async def _learn_from_node(self, node: RemoteUrsula):
        self._logger.debug("Learning from {}", node)
        ssl_contact = node.ssl_contact
        metadata_response = await self._rest_client.node_metadata_post(
            ssl_contact, self.fleet_state_checksum, self.metadata_to_announce())

        payload = metadata_response.verify(node.metadata.payload.verifying_key)

        # TODO: make use of the returned timestamp

        self.add_metadata(payload.announce_nodes)

    async def learning_round(self):

        if self._seed_contacts:
            teacher_contact = random.choice(self._seed_contacts)
            await self._learn_from_contact(teacher_contact)
            self._seed_contacts = None
            return

        # Choose whether we get a verified or an unverified node to learn from
        unverified_num = len(self._unverified_nodes)
        verified_num = len(self._verified_nodes)

        if unverified_num + verified_num == 0:
            # No nodes to learn from, have to wait until someone leaves us a contact.
            return

        idx = random.randrange(verified_num + unverified_num)
        learn_from_verified = idx < verified_num

        if learn_from_verified:
            addresses = list(self._verified_nodes)
            teacher_address = random.choice(addresses)
            teacher_node = self._verified_nodes[teacher_address]
            await self._learn_from_node(teacher_node)

        else:
            addresses = list(self._unverified_nodes)
            teacher_address = random.choice(addresses)
            teacher_metadata = self._unverified_nodes[teacher_address]

            ssl_contact = SSLContact.from_metadata(teacher_metadata)

            remote_metadata = await self._rest_client.public_information(ssl_contact)
            assert metadata_is_consistent(teacher_metadata, remote_metadata)
            # Note that we are using the metadata we got from the node itself
            teacher_node = await self._verify_metadata(remote_metadata)
            await self._learn_from_node(teacher_node)
