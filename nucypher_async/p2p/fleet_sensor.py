from collections import defaultdict
from contextlib import contextmanager
import random

import trio

from ..drivers.eth_client import Address
from ..drivers.rest_client import Contact


class FleetSensor:

    def __init__(self, my_staker_address, seed_contacts=None):

        self._my_staker_address = my_staker_address

        self._contacts_to_addresses = defaultdict(set)
        self._addresses_to_contacts = defaultdict(set)
        self._verified_nodes = {}

        self._locked_contacts = set()
        self._locked_nodes = set()

        self._verified_nodes_updated = trio.Event()
        self._addresses_updated = trio.Event()

        if seed_contacts:
            for contact in seed_contacts:
                self._contacts_to_addresses[contact] = set()

    def has_unchecked_contacts(self):
        return bool(self._contacts_to_addresses.keys() - self._locked_contacts)

    def has_verified_nodes(self):
        return bool(self._verified_nodes.keys() - self._locked_nodes)

    @contextmanager
    def lock_unchecked_contact(self):
        # TODO: here we may pick a contact that was supplied by the most nodes
        contact = random.choice(list(self._contacts_to_addresses.keys() - self._locked_contacts))
        self._locked_contacts.add(contact)
        yield contact
        self._locked_contacts.remove(contact)

    @contextmanager
    def lock_verified_node(self):
        # TODO: here we can pick a node that hasn't been re-verified for a long time
        address = random.choice(list(self._verified_nodes.keys() - self._locked_nodes))
        node = self._verified_nodes[address]
        self._locked_nodes.add(address)
        yield node
        self._locked_nodes.remove(address)

    def _add_contact(self, contact, staker_address):
        if staker_address in self._verified_nodes:
            return

        address_updated = (
            staker_address not in self._addresses_to_contacts
            or contact not in self._addresses_to_contacts[staker_address])

        self._contacts_to_addresses[contact].add(staker_address)
        self._addresses_to_contacts[staker_address].add(contact)

        return address_updated

    def add_contacts(self, metadatas):
        addresses_updated = False
        for metadata in metadatas:
            payload = metadata.payload
            staker_address = Address(payload.staker_address)

            if self._my_staker_address and staker_address == self._my_staker_address:
                continue

            new_contact = Contact(payload.host, payload.port)
            address_updated = self._add_contact(new_contact, staker_address)
            addresses_updated = address_updated or addresses_updated

        if addresses_updated:
            self._addresses_updated.set()
            self._addresses_updated = trio.Event()

    def add_verified_node(self, node):
        if node.staker_address not in self._verified_nodes:
            # This means it may be in contacts.
            # Need to clean it out to ensure consistency.
            contact = node.ssl_contact.contact
            address = node.staker_address

            if contact in self._contacts_to_addresses:
                associated_addresses = self._contacts_to_addresses[contact]
                for address in associated_addresses:
                    self._addresses_to_contacts[address].remove(contact)
                del self._contacts_to_addresses[contact]

            if address in self._addresses_to_contacts:
                associated_contacts = self._addresses_to_contacts[address]
                for contact in associated_contacts:
                    self._contacts_to_addresses[contact].remove(address)
                del self._addresses_to_contacts[address]

            self._verified_nodes_updated.set()
            self._verified_nodes_updated = trio.Event()

        # This is the most recent metadata we got from the node, add it.
        self._verified_nodes[node.staker_address] = node

    def remove_verified_node(self, node):
        if node.staker_address not in self._verified_nodes:
            return

        del self._verified_nodes[node.staker_address]

    def report_verified_node(self, node):
        # TODO
        pass

    def verified_metadata(self):
        return [node.metadata for node in self._verified_nodes.values()]
