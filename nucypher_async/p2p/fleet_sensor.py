from collections import defaultdict
from contextlib import contextmanager
import datetime
import random
from typing import NamedTuple

import arrow
from sortedcontainers import SortedKeyList
import trio

from ..drivers.identity import IdentityAddress
from ..drivers.rest_client import Contact
from ..ursula import RemoteUrsula


class NodeEntry(NamedTuple):
    node: RemoteUrsula
    verified_at: arrow.Arrow


class VerifyAtEntry(NamedTuple):
    address: IdentityAddress
    verify_at: arrow.Arrow


class VerifiedNodesDB:

    def __init__(self):
        self._nodes = {}
        self._locked_for_verification = set()
        self._locked_for_learning = set()
        self._verify_at = SortedKeyList(key=lambda entry: entry.verify_at)
        self._updated = trio.Event()

    def add_node(self, node, now, verify_at):
        assert node.staking_provider_address not in self._nodes

        self._updated.set()
        self._updated = trio.Event()

        self._nodes[node.staking_provider_address] = NodeEntry(
            node=node,
            verified_at=now)
        self._verify_at.add(VerifyAtEntry(
            address=node.staking_provider_address,
            verify_at=verify_at))

    def get_verified_at(self, node):
        return self._nodes[node.staking_provider_address].verified_at

    def set_verified_at(self, node, verify_at):
        assert node.staking_provider_address in self._nodes
        self._verify_at.add(VerifyAtEntry(
            address=node.staking_provider_address, verify_at=verify_at))

    def remove_node(self, node):
        del self._nodes[node.staking_provider_address]
        # TODO: we really need a SortedDict type
        for i in range(len(self._verify_at)):
            if self._verify_at[i] == node.staking_provider_address:
                del self._verify_at[i]
                break

    def all_nodes(self):
        return [entry.node for entry in self._nodes.values()]

    def has_contact(self, contact):
        return any(entry.node.ssl_contact.contact == contact for entry in self._nodes.values())

    def is_empty(self):
        return bool(self._nodes)

    def next_event_in(self, now):
        for entry in self._verify_at:
            if entry.address not in self._locked_for_verification:
                return entry.verify_at - now
        return None

    @contextmanager
    def try_lock_node_to_learn_from(self, node=None):
        if node is None:
            # TODO: here we might pick a node we haven't learned from for the longest time
            addresses = list(self._nodes.keys() - self._locked_for_learning - self._locked_for_verification)
            if not addresses:
                yield None
                return
            address = random.choice(addresses)
        else:
            if (node.staking_provider_address in self._locked_for_learning
                    or node.staking_provider_address in self._locked_for_verification):
                yield None
                return
            address = node.staking_provider_address

        node = self._nodes[address].node
        self._locked_for_learning.add(address)
        try:
            yield node
        finally:
            self._locked_for_learning.remove(address)

    @contextmanager
    def try_lock_node_to_verify(self, now):
        for entry in self._verify_at:

            if entry.verify_at > now:
                yield None
                break

            if (entry.address not in self._locked_for_learning
                    and entry.address not in self._locked_for_verification):
                try:
                    self._locked_for_verification.add(entry.address)
                    yield node
                finally:
                    self._locked_for_verification.remove(entry.address)
                break
        else:
            yield None


class ContactsDB:

    def __init__(self):
        self._contacts_to_addresses = defaultdict(set)
        self._addresses_to_contacts = defaultdict(set)
        self._locked_contacts = set()
        self._updated = trio.Event()

    @contextmanager
    def try_lock_contact_to_verify(self):
        contacts = list(self._contacts_to_addresses.keys() - self._locked_contacts)
        if not contacts:
            yield None
            return
        # TODO: choose the contact that was supplied by the majority of nodes
        # This will help neutralize contact spam from malicious nodes.
        contact = random.choice(contacts)
        self._locked_contacts.add(contact)
        try:
            yield contact
        finally:
            self._locked_contacts.remove(contact)

    def add_contact(self, contact, address=None):
        updated = (
            address is not None
            and (address not in self._addresses_to_contacts
                or contact not in self._addresses_to_contacts[address]))

        if address is not None:
            self._contacts_to_addresses[contact].add(address)
            self._addresses_to_contacts[address].add(contact)
        else:
            self._contacts_to_addresses[contact]

        # TODO: if that takes too long we may want to have a batch `add_contacts()` instead
        if updated:
            self._updated.set()
            self._updated = trio.Event()

    def remove_contact(self, contact):
        if contact in self._contacts_to_addresses:
            associated_addresses = self._contacts_to_addresses[contact]
            for address in associated_addresses:
                self._addresses_to_contacts[address].remove(contact)
                if len(self._addresses_to_contacts[address]) == 0:
                    del self._addresses_to_contacts[address]
            del self._contacts_to_addresses[contact]

    def remove_address(self, address):
        if address in self._addresses_to_contacts:
            associated_contacts = self._addresses_to_contacts[address]
            for contact in associated_contacts:
                self._contacts_to_addresses[contact].remove(address)
                # Not cleaning up empty entries from `_contacts_to_addresses`,
                # because a contact without a known address is still useful.
            del self._addresses_to_contacts[address]

    def is_empty(self):
        return bool(self._contacts_to_addresses)

    def has_unlocked_contacts(self):
        return bool(self._contacts_to_addresses.keys() - self._locked_contacts)


class FleetSensor:

    def __init__(self, clock, my_staking_provider_address, my_contact, seed_contacts=None):

        self._clock = clock

        self._my_staking_provider_address = my_staking_provider_address
        self._my_contact = my_contact

        self._verified_nodes_db = VerifiedNodesDB()
        self._contacts_db = ContactsDB()

        self._seed_contacts = seed_contacts
        self._add_seed_contacts()

    def report_bad_contact(self, contact):
        self._contacts_db.remove_contact(contact)

    def report_bad_node(self, node):
        self._verified_nodes_db.remove_node(node)

    def report_verified_node(self, node):
        self._contacts_db.remove_contact(node.ssl_contact.contact)
        self._contacts_db.remove_address(node.staking_provider_address)

        now = self._clock.utcnow()
        verify_at = self._calculate_next_verification(node, now)
        self._verified_nodes_db.add_node(node, now, verify_at)

    def _calculate_next_verification(self, node, now, previously_verified_at=None):

        if previously_verified_at:
            assert now > previously_verified_at
            verify_at = now + (now - previously_verified_at) * 1.5 # TODO: remove hardcoding
        else:
            verify_at = now.shift(hours=1)

        # If there's certificate expiry incoming, verify then
        certificate_expires_at = node.ssl_contact.certificate.not_valid_after
        verify_at = min(certificate_expires_at.shift(seconds=1), verify_at)

        # TODO: other limits for increasing the verification interval are possible.
        # How big is the unstaking timeout?

        assert verify_at > now

        return verify_at

    def report_reverified_node(self, old_node, new_node):
        if bytes(new_node.metadata) == bytes(old_node.metadata):
            previously_verified_at = self._verified_nodes_db.get_verified_at(node)
            now = self._clock.utcnow()
            verify_at = self._calculate_next_verification(old_node, now, previously_verified_at)
            self._verified_nodes_db.set_verify_at(node, verify_at)
            return
        self._verified_nodes_db.remove_node(old_node)
        self._verified_nodes_db.add_node(new_node)

    def report_active_learning_results(self, teacher_node, metadatas):
        for metadata in metadatas:
            payload = metadata.payload
            contact = Contact(payload.host, payload.port)
            if contact == teacher_node.ssl_contact.contact and bytes(metadata) != bytes(teacher_node.metadata):
                self._verified_nodes_db.remove_node(teacher_node)
        self._add_contacts(metadatas)

    def report_passive_learning_results(self, sender_host, metadatas):

        # Filter out only the contact(s) with `remote_address`.
        # We're not going to trust all this metadata anyway.
        sender_metadatas = [
            metadata for metadata in metadatas
            if metadata.payload.host == sender_host]
        self._add_contacts(sender_metadatas)

    def verified_metadata(self):
        return [node.metadata for node in self._verified_nodes_db.all_nodes()]

    def _add_contacts(self, metadatas):
        for metadata in metadatas:
            payload = metadata.payload
            contact = Contact(payload.host, payload.port)
            address = IdentityAddress(payload.staking_provider_address)
            if (contact != self._my_contact
                    and address != self._my_staking_provider_address
                    and not self._verified_nodes_db.has_contact(contact)):
                self._contacts_db.add_contact(contact, payload.staking_provider_address)

    def next_verification_in(self) -> datetime.timedelta:

        # If there is nothing to learn from, reintroduce seed contacts
        if self._contacts_db.is_empty() and not self._verified_nodes_db.is_empty():
            self._add_seed_contacts()

        # If there are contacts to check, do it asap
        if self._contacts_db.has_unlocked_contacts():
            return datetime.timedelta()

        now = self._clock.utcnow()
        next_event_in = self._verified_nodes_db.next_event_in(now)
        if next_event_in is None:
            return datetime.timedelta(days=1)
        else:
            return next_event_in

    @contextmanager
    def try_lock_contact_to_verify(self):
        with self._contacts_db.try_lock_contact_to_verify() as contact:
            yield contact

    @contextmanager
    def try_lock_node_to_verify(self):
        now = self._clock.utcnow()
        with self._verified_nodes_db.try_lock_node_to_verify(now) as node:
            yield node

    @contextmanager
    def try_lock_node_to_learn_from(self, node=None):
        with self._verified_nodes_db.try_lock_node_to_learn_from(node) as node:
            yield node

    def _add_seed_contacts(self):
        if self._seed_contacts:
            for contact in self._seed_contacts:
                self._contacts_db.add_contact(contact)

    # ---

    def addresses_are_known(self, addresses: set):
        return not bool(
            addresses
            - self._addresses_to_contacts.keys()
            - self._verified_nodes.keys())

    def try_get_verified_node(self, address):
        return self._verified_nodes.get(address, None)

    def try_get_possible_contacts(self, address):
        contacts = self._addresses_to_contacts.get(address, [])
        return set(contacts) - self._locked_contacts
