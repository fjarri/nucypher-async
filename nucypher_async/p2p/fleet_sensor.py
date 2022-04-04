from collections import defaultdict
from contextlib import contextmanager
import datetime
import random
from typing import NamedTuple

import arrow
from sortedcontainers import SortedKeyList
import trio

from ..drivers.identity import IdentityAddress, AmountT
from ..drivers.rest_client import Contact
from ..ursula import RemoteUrsula


class NodeEntry(NamedTuple):
    node: RemoteUrsula
    verified_at: arrow.Arrow
    staked_amount: AmountT


class VerifyAtEntry(NamedTuple):
    address: IdentityAddress
    verify_at: arrow.Arrow


class VerifiedNodesDB:

    def __init__(self):
        self._nodes = {}
        self._verify_at = SortedKeyList(key=lambda entry: entry.verify_at)

    def add_node(self, node, staked_amount, verified_at, verify_at):
        assert node.staking_provider_address not in self._nodes
        self._nodes[node.staking_provider_address] = NodeEntry(
            node=node,
            verified_at=verified_at,
            staked_amount=staked_amount)
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

    def next_verification_in(self, now, exclude):
        for entry in self._verify_at:
            if entry.address not in exclude:
                return entry.verify_at - now
        return None

    def get_next_verification(self, now, exclude):
        for entry in self._verify_at:
            if entry.verify_at > now:
                return None

            if entry.address not in exclude:
                return entry.address

        return None


class ContactsDB:

    def __init__(self):
        self._contacts_to_addresses = defaultdict(set)
        self._addresses_to_contacts = defaultdict(set)

    def get_next_verification(self, exclude):
        contacts = list(self._contacts_to_addresses.keys() - exclude)
        if not contacts:
            return None

        # TODO: choose the contact that was supplied by the majority of nodes
        # This will help neutralize contact spam from malicious nodes.
        return random.choice(contacts)

    def add_contact(self, contact, address=None):

        new_contact = contact not in self._contacts_to_addresses
        new_contact_for_address = False

        if address is not None:
            new_contact_for_address = contact not in self._addresses_to_contacts[address]
            self._contacts_to_addresses[contact].add(address)
            self._addresses_to_contacts[address].add(contact)
        else:
            self._contacts_to_addresses[contact]

        return new_contact, new_contact_for_address

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


class FleetSensor:

    def __init__(self, clock, my_staking_provider_address, my_contact, seed_contacts=None):

        self._clock = clock

        self._my_staking_provider_address = my_staking_provider_address
        self._my_contact = my_contact

        self._verified_nodes_db = VerifiedNodesDB()
        self._contacts_db = ContactsDB()

        self._locked_verified_addresses = set()
        self._locked_contacts = set()

        self._new_verified_nodes = trio.Event()
        self._new_contacts = trio.Event()
        self._new_contacts_for_address = trio.Event()

        self._seed_contacts = seed_contacts
        self._add_seed_contacts()

    def _calculate_next_verification(self, node, verified_at, previously_verified_at=None):

        if previously_verified_at:
            assert verified_at > previously_verified_at
            verify_at = verified_at + (verified_at - previously_verified_at) * 1.5 # TODO: remove hardcoding
        else:
            verify_at = verified_at.shift(hours=1)

        # If there's certificate expiry incoming, verify then
        certificate_expires_at = node.ssl_contact.certificate.not_valid_after
        verify_at = min(certificate_expires_at.shift(seconds=1), verify_at)

        # TODO: other limits for increasing the verification interval are possible.
        # How big is the unstaking timeout?

        assert verify_at > verified_at

        return verify_at

    def report_bad_contact(self, contact):
        self._contacts_db.remove_contact(contact)

    def report_bad_node(self, node):
        self._verified_nodes_db.remove_node(node)

    def report_verified_node(self, node, staked_amount):
        self._contacts_db.remove_contact(node.ssl_contact.contact)
        self._contacts_db.remove_address(node.staking_provider_address)

        verified_at = self._clock.utcnow()
        verify_at = self._calculate_next_verification(node, verified_at)
        self._add_node(node, staked_amount, verified_at, verify_at)

    def report_reverified_node(self, old_node, new_node, staked_amount):
        verified_at = self._clock.utcnow()
        if bytes(new_node.metadata) == bytes(old_node.metadata):
            previously_verified_at = self._verified_nodes_db.get_verified_at(node)
            verify_at = self._calculate_next_verification(old_node, verified_at, previously_verified_at)
            self._verified_nodes_db.set_verify_at(node, verify_at)
        else:
            self._verified_nodes_db.remove_node(old_node)
            verify_at = self._calculate_next_verification(new_node, verified_at)
            self._add_node(new_node, staked_amount, verified_at, verify_at)

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

    def _add_node(self, node, staked_amount, verified_at, verify_at):
        self._verified_nodes_db.add_node(node, staked_amount, verified_at, verify_at)
        self._new_verified_nodes.set()
        self._new_verified_nodes = trio.Event()

    def _add_contacts(self, metadatas):
        new_contacts = False
        new_contacts_for_address = False
        for metadata in metadatas:
            payload = metadata.payload
            contact = Contact(payload.host, payload.port)
            address = IdentityAddress(payload.staking_provider_address)

            if self._my_contact:
                if contact == self._my_contact or address == self._my_staking_provider_address:
                    continue

            if self._verified_nodes_db.has_contact(contact):
                continue

            new_contact, new_contact_for_address = self._contacts_db.add_contact(contact, address)

            new_contacts = new_contacts or new_contact
            new_contacts_for_address = new_contacts_for_address or new_contact_for_address

        if new_contacts:
            self._new_contacts.set()
            self._new_contacts = trio.Event()

        if new_contacts_for_address:
            self._new_contacts_for_address.set()
            self._new_contacts_for_address = trio.Event()

    def next_learning_in(self) -> datetime.timedelta:
        # TODO: May be adjusted dynamically based on the network state
        return datetime.timedelta(seconds=90)

    def next_verification_in(self) -> datetime.timedelta:

        # If there is nothing to learn from, reintroduce seed contacts
        if self._contacts_db.is_empty() and not self._verified_nodes_db.is_empty():
            self._add_seed_contacts()

        # If there are contacts to check, do it asap
        if self._contacts_db.get_next_verification(self._locked_contacts):
            return datetime.timedelta()

        now = self._clock.utcnow()
        next_verification_in = self._verified_nodes_db.next_verification_in(now, exclude=self._locked_verified_addresses)
        if next_verification_in is None:
            # Maybe someone will contact us during this time and leave some contacts.
            return datetime.timedelta(days=1)
        else:
            return next_verification_in

    @contextmanager
    def try_lock_contact_to_verify(self, contact=None):
        if contact is None:
            contact = self._contacts_db.get_next_verification(self._locked_contacts)
            if contact is None:
                yield None
                return
        else:
            if contact in self._locked_contacts:
                yield None
                return

        self._locked_contacts.add(contact)
        try:
            yield contact
        finally:
            self._locked_contacts.remove(contact)

    @contextmanager
    def try_lock_node_to_learn_from(self, node=None):
        if node is None:
            # TODO: here we might pick a node we haven't learned from for the longest time
            addresses = list(self._verified_nodes_db._nodes.keys() - self._locked_verified_addresses)
            if not addresses:
                yield None
                return
            address = random.choice(addresses)
        else:
            if node.staking_provider_address in self._locked_verified_addresses:
                yield None
                return
            address = node.staking_provider_address

        node = self._verified_nodes_db._nodes[address].node
        self._locked_verified_addresses.add(address)
        try:
            yield node
        finally:
            self._locked_verified_addresses.remove(address)

    @contextmanager
    def try_lock_node_to_verify(self):
        now = self._clock.utcnow()
        node = self._verified_nodes_db.get_next_verification(now, exclude=self._locked_verified_addresses)
        if node is None:
            yield None
            return

        self._locked_verified_addresses.add(node.staking_provider_address)
        try:
            yield node
        finally:
            self._locked_verified_addresses.remove(node.staking_provider_address)

    def _add_seed_contacts(self):
        if self._seed_contacts:
            for contact in self._seed_contacts:
                self._contacts_db.add_contact(contact)

    # ---

    @property
    def verified_node_entries(self):
        return self._verified_nodes_db._nodes

    def try_get_possible_contacts_for(self, address):
        contacts = self._contacts_db._addresses_to_contacts.get(address, [])
        return set(contacts) - self._locked_contacts

    def print_status(self):
        print("Verified nodes:")
        for entry in self._verified_nodes_db._nodes.values():
            print(entry)
        print()
        print("Verification queue:")
        for entry in self._verified_nodes_db._verify_at:
            print(entry)
        print()
        print("Locked verified nodes:")
        print(self._locked_verified_addresses)
        print()
        print("Contacts to addresses:")
        for contact, addresses in self._contacts_db._contacts_to_addresses.items():
            print(f"{contact}: {addresses}")
        print()
        print("Addresses to contacts:")
        for address, contacts in self._contacts_db._addresses_to_contacts.items():
            print(f"{address}: {contacts}")
        print()
        print("Locked contacts:")
        print(self._locked_contacts)
