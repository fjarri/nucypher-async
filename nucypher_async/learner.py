from collections import defaultdict
import random
from typing import Optional

import trio

from .protocol import ContactPackage, Metadata, NodeID, SignedContact, ContactRequest
from .middleware import NetworkClient
from .utils import BackgroundTask, Contact


class Learner:
    """
    The client for P2P network of Ursulas, keeping the metadata of known nodes
    and running the background learning task.
    """

    def __init__(self, middleware, my_metadata=None, seed_contacts=None):
        self._client = NetworkClient(middleware)

        self._my_metadata = my_metadata

        self._seed_contacts = seed_contacts

        # unverified contacts
        self._contacts = {} # node id -> signed contact

        # verified contacts: node id -> node metadata
        self._verified_nodes = {}

        self._nodes_updated = trio.Event()

    async def add_contact(self, signed_contact: SignedContact):
        # Assuming here that the signature is verified on deserialization
        # TODO: check the timestamp here, and only update if the timestamp is newer
        if self._my_metadata and signed_contact.node_id == self._my_metadata.node_id:
            return
        if signed_contact.node_id not in self._contacts and signed_contact.node_id not in self._verified_nodes:
            self._contacts[signed_contact.node_id] = signed_contact

    def verified_contact_package(self) -> ContactPackage:
        contacts = [metadata.signed_contact for metadata in self._verified_nodes.values()]
        assert self._my_metadata # only Ursulas are supposed to send their contacts
        return ContactPackage(self._my_metadata, contacts)

    async def knows_nodes(self, ursula_ids):
        ids_set = set(ursula_ids)
        while True:
            if ids_set.issubset(self._verified_nodes):
                return {id: self._verified_nodes[id] for id in ids_set}
            await self._nodes_updated.wait()

    def _verify_node(self, ssl_contact, metadata, expected_node_id=None):

        # TODO: test that metadata is signed with node id

        assert metadata.ssl_contact == ssl_contact
        if expected_node_id:
            assert metadata.node_id == expected_node_id

        # TODO: test that the node id is a staker etc

    async def _learn_from_unverified_node(self, contact: Contact, node_id=None):
        # TODO: what if there's someone else at that address? Process certificate failure.
        # What if someone got the SSL private key, but not the other stuff? Should we re-verify metadata?
        ssl_contact = await self._client.fetch_certificate(contact)
        contact_request = ContactRequest(self._my_metadata.signed_contact if self._my_metadata else None)
        contact_package = await self._client.get_contacts(ssl_contact, contact_request)

        try:
            self._verify_node(ssl_contact, contact_package.metadata, expected_node_id=node_id)
        except Exception as e:
            # TODO: remove from contacts?
            raise Exception("Verification error") from e

        if node_id:
            del self._contacts[node_id]
        else:
            node_id = contact_package.metadata.node_id

        self._verified_nodes[node_id] = contact_package.metadata

        # Release whoever was waiting for the state to be updated
        # TODO: only do so if there was a change in the state.
        self._nodes_updated.set()
        await trio.sleep(0) # TODO: is it necessary?
        self._nodes_updated = trio.Event()

        for contact in contact_package.contacts:
            await self.add_contact(contact)

    async def _learn_from_verified_node(self, metadata: Metadata):
        contact_request = ContactRequest(self._my_metadata.signed_contact if self._my_metadata else None)
        contact_package = await self._client.get_contacts(metadata.ssl_contact, contact_request)
        # TODO: if fails, unverify the node

        if metadata != contact_package.metadata:
            # TODO: unverify the node or update the metadata
            return

        for contact in contact_package.contacts:
            await self.add_contact(contact)

    async def learning_round(self):

        if self._seed_contacts:
            teacher_contact = random.choice(self._seed_contacts)
            await self._learn_from_unverified_node(teacher_contact)
            self._seed_contacts = None
            return

        # Choose whether we get a verified or an unverified node to learn from
        unverified_num = len(self._contacts)
        verified_num = len(self._verified_nodes)

        if unverified_num + verified_num == 0:
            # No nodes to learn from, have to wait until someone leaves us a contact.
            return

        idx = random.randrange(verified_num + unverified_num)
        learn_from_verified = idx < verified_num

        if learn_from_verified:
            node_ids = list(self._verified_nodes)
            teacher_id = random.choice(node_ids)
            teacher_metadata = self._verified_nodes[teacher_id]
            await self._learn_from_verified_node(teacher_metadata)

        else:
            node_ids = list(self._contacts)
            teacher_id = random.choice(node_ids)
            teacher_signed_contact = self._contacts[teacher_id]
            await self._learn_from_unverified_node(teacher_signed_contact.contact, node_id=teacher_id)
