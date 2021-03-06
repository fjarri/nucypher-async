from collections import defaultdict
from contextlib import contextmanager
import datetime
import random
from typing import NamedTuple

import arrow
from sortedcontainers import SortedKeyList
import trio

from ..drivers.identity import IdentityAddress, AmountT
from ..drivers.peer import Contact
from ..verification import PublicUrsula


class NodeEntry(NamedTuple):
    node: PublicUrsula
    verified_at: arrow.Arrow
    staked_amount: AmountT


class VerifyAtEntry(NamedTuple):
    address: IdentityAddress
    verify_at: arrow.Arrow


class StakingProviderEntry(NamedTuple):
    address: IdentityAddress
    contact: Contact
    weight: AmountT


class BroadcastedValue:

    def __init__(self):
        self._value = None
        self._event = trio.Event()

    def set(self, value):
        self._value = value
        self._event.set()

    async def wait(self):
        await self._event.wait()
        return self._value


class VerifiedNodesDB:

    def __init__(self):
        self._nodes = {}
        self._verify_at = SortedKeyList(key=lambda entry: entry.verify_at)

    def add_node(self, node, staked_amount, verified_at, verify_at):
        assert node.staking_provider_address not in self._nodes
        assert not any(entry.node.secure_contact.contact == node.secure_contact.contact for entry in self._nodes.values())
        self._nodes[node.staking_provider_address] = NodeEntry(
            node=node,
            verified_at=verified_at,
            staked_amount=staked_amount)
        self._verify_at.add(VerifyAtEntry(
            address=node.staking_provider_address,
            verify_at=verify_at))

    def _del_verify_at(self, node):
        # TODO: we really need a SortedDict type
        for i in range(len(self._verify_at)):
            if self._verify_at[i].address == node.staking_provider_address:
                del self._verify_at[i]
                break

    def get_verified_at(self, node):
        return self._nodes[node.staking_provider_address].verified_at

    def update_verify_at(self, node, verified_at, verify_at):
        assert node.staking_provider_address in self._nodes

        node_entry = self._nodes[node.staking_provider_address]._replace(verified_at=verified_at)
        self._nodes[node.staking_provider_address] = node_entry

        self._del_verify_at(node)
        self._verify_at.add(VerifyAtEntry(
            address=node.staking_provider_address, verify_at=verify_at))

    def remove_node(self, node):
        del self._nodes[node.staking_provider_address]
        self._del_verify_at(node)

    def remove_by_contact(self, contact):
        for address, entry in self._nodes.items():
            if entry.node.secure_contact.contact == contact:
                del self._nodes[address]
                self._del_verify_at(entry.node)
                break

    def all_nodes(self):
        return [entry.node for entry in self._nodes.values()]

    def has_contact(self, contact):
        return any(entry.node.secure_contact.contact == contact for entry in self._nodes.values())

    def is_empty(self):
        return not bool(self._nodes)

    def next_verification_at(self, exclude):
        for entry in self._verify_at:
            if self._nodes[entry.address].node.secure_contact.contact not in exclude:
                return entry.verify_at
        return None

    def next_verification_in(self, now, exclude):
        time_point = self.next_verification_at(exclude)
        if time_point:
            return time_point - now if time_point > now else datetime.timedelta()
        else:
            return None

    def get_contacts_to_verify(self, now, contacts_num, exclude):
        contacts = []
        for entry in self._verify_at:
            if entry.verify_at > now:
                return contacts

            contact = self._nodes[entry.address].node.secure_contact.contact
            if contact not in exclude:
                contacts.append(contact)

        return contacts


class ContactsDB:

    def __init__(self):
        self._contacts_to_addresses = defaultdict(set)
        self._addresses_to_contacts = defaultdict(set)

    def get_contacts_to_verify(self, contacts_num, exclude):
        contacts = list(self._contacts_to_addresses.keys() - exclude)

        # TODO: choose the contact that was supplied by the majority of nodes
        # This will help neutralize contact spam from malicious nodes.
        return random.sample(contacts, min(contacts_num, len(contacts)))

    def add_contact(self, contact, address=None):
        if address is not None:
            self._contacts_to_addresses[contact].add(address)
            self._addresses_to_contacts[address].add(contact)
        else:
            self._contacts_to_addresses[contact]

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
        return not bool(self._contacts_to_addresses)


def _next_verification_time_may_change(func):

    def wrapped(fleet_sensor, *args, **kwargs):

        contacts_present_before = not fleet_sensor._contacts_db.is_empty()
        next_verification_before = fleet_sensor._verified_nodes_db.next_verification_at(
            exclude=fleet_sensor._locked_contacts.keys())

        result = func(fleet_sensor, *args, **kwargs)

        contacts_present_after = not fleet_sensor._contacts_db.is_empty()
        next_verification_after = fleet_sensor._verified_nodes_db.next_verification_at(
            exclude=fleet_sensor._locked_contacts.keys())

        reschedule = (
            (contacts_present_after and not contacts_present_before)
            or (next_verification_before is None and next_verification_after is not None)
            or (
                next_verification_before is not None
                and next_verification_after is not None
                and next_verification_after < next_verification_before)
            )

        if reschedule:
            fleet_sensor.reschedule_verification_event.set()
            fleet_sensor.reschedule_verification_event = trio.Event()

        return result

    return wrapped


class FleetSensor:

    def __init__(self, clock, my_staking_provider_address, my_contact):

        self._clock = clock

        self._my_staking_provider_address = my_staking_provider_address
        self._my_contact = my_contact

        self._verified_nodes_db = VerifiedNodesDB()
        self._contacts_db = ContactsDB()
        self._staking_providers = {}
        self._staking_providers_updated = None

        self._locked_contacts = dict()

        self.new_verified_nodes_event = trio.Event()
        self.reschedule_verification_event = trio.Event()

    def _calculate_next_verification(self, node, verified_at, previously_verified_at=None):

        if previously_verified_at:
            assert verified_at > previously_verified_at
            verify_at = verified_at + (verified_at - previously_verified_at) * 1.5 # TODO: remove hardcoding
        else:
            verify_at = verified_at.shift(hours=1)

        # If there's public key expiry incoming, verify then
        expires_at = node.secure_contact.not_valid_after
        verify_at = min(expires_at.shift(seconds=1), verify_at)

        # TODO: other limits for increasing the verification interval are possible.
        # How big is the unstaking timeout?

        assert verify_at > verified_at

        return verify_at

    @_next_verification_time_may_change
    def report_bad_contact(self, contact):
        self._contacts_db.remove_contact(contact)
        self._verified_nodes_db.remove_by_contact(contact)

    @_next_verification_time_may_change
    def report_verified_node(self, contact, node, staked_amount):

        verified_at = self._clock.utcnow()

        # Note that we do not use the node's `secure_contact`:
        # `contact` might have an unresolved hostname, but `node` will have a resolved IP.
        # TODO: IPs should be typed properly.
        self._contacts_db.remove_contact(contact)
        self._contacts_db.remove_address(node.staking_provider_address)

        entry_by_staker = self._verified_nodes_db._nodes.get(node.staking_provider_address, None)

        if not entry_by_staker:
            # New verification

            # This IP may have had another staking provider associated with it, unverify the old one
            # (if it is the same node, no harm done, we're doing _add_node() anyway).
            self._verified_nodes_db.remove_by_contact(node.secure_contact.contact)

            verify_at = self._calculate_next_verification(node, verified_at)
            self._add_node(node, staked_amount, verified_at, verify_at)

        else:
            # Re-verification
            old_node = entry_by_staker.node

            if bytes(node.metadata) == bytes(old_node.metadata):
                previously_verified_at = self._verified_nodes_db.get_verified_at(node)
                verify_at = self._calculate_next_verification(node, verified_at, previously_verified_at)
                self._verified_nodes_db.update_verify_at(node, verified_at, verify_at)
            else:
                self._verified_nodes_db.remove_node(old_node)
                verify_at = self._calculate_next_verification(node, verified_at)
                self._add_node(node, staked_amount, verified_at, verify_at)

    @_next_verification_time_may_change
    def report_active_learning_results(self, teacher_node, metadatas):
        for metadata in metadatas:
            payload = metadata.payload
            contact = Contact(payload.host, payload.port)
            if contact == teacher_node.secure_contact.contact and bytes(metadata) != bytes(teacher_node.metadata):
                self._verified_nodes_db.remove_node(teacher_node)
        self._add_contacts(metadatas)

    @_next_verification_time_may_change
    def report_passive_learning_results(self, sender_host, metadatas):

        # Filter out only the contact(s) with `remote_address`.
        # We're not going to trust all this metadata anyway.
        sender_metadatas = [
            metadata for metadata in metadatas
            if metadata.payload.host == sender_host]
        self._add_contacts(sender_metadatas)

    @_next_verification_time_may_change
    def report_staking_providers(self, providers):
        self._staking_providers = providers
        self._staking_providers_updated = self._clock.utcnow()

    def verified_metadata(self):
        return [node.metadata for node in self._verified_nodes_db.all_nodes()]

    def _add_node(self, node, staked_amount, verified_at, verify_at):
        self._verified_nodes_db.add_node(node, staked_amount, verified_at, verify_at)
        self.new_verified_nodes_event.set()
        self.new_verified_nodes_event = trio.Event()

    def _add_contacts(self, metadatas):
        for metadata in metadatas:
            payload = metadata.payload
            contact = Contact(payload.host, payload.port)
            address = IdentityAddress(payload.staking_provider_address)

            if self._my_contact:
                if contact == self._my_contact or address == self._my_staking_provider_address:
                    continue

            if self._verified_nodes_db.has_contact(contact):
                continue

            self._contacts_db.add_contact(contact, address)

    def next_learning_in(self) -> datetime.timedelta:
        # TODO: May be adjusted dynamically based on the network state
        return datetime.timedelta(seconds=90).total_seconds()

    def is_empty(self):
        return self._contacts_db.is_empty() and self._verified_nodes_db.is_empty()

    def next_verification_in(self) -> datetime.timedelta:

        if self._contacts_db.is_empty() and self._verified_nodes_db.is_empty():
            return datetime.timedelta.max.total_seconds()

        # If there are contacts to check, do it asap
        if not self._contacts_db.is_empty():
            return datetime.timedelta().total_seconds()

        now = self._clock.utcnow()
        next_verification_in = self._verified_nodes_db.next_verification_in(now, exclude=self._locked_contacts.keys())
        if next_verification_in is None:
            # Maybe someone will contact us during this time and leave some contacts.
            return datetime.timedelta(days=1).total_seconds()
        else:
            return next_verification_in.total_seconds()

    @contextmanager
    def try_lock_contact(self, contact):
        if contact in self._locked_contacts:
            yield None, self._locked_contacts[contact]
            return

        bval = BroadcastedValue()
        self._locked_contacts[contact] = bval
        try:
            yield contact, bval
        finally:
            del self._locked_contacts[contact]

    def get_contacts_to_verify(self, contacts_num):
        return self._contacts_db.get_contacts_to_verify(contacts_num, exclude=self._locked_contacts.keys())

    def get_contacts_to_reverify(self, contacts_num):
        now = self._clock.utcnow()
        return self._verified_nodes_db.get_contacts_to_verify(now, contacts_num, exclude=self._locked_contacts.keys())

    def get_nodes_to_learn_from(self, nodes_num):
        entries = [
            entry for entry in self._verified_nodes_db._nodes.values()
            if entry.node.secure_contact.contact not in self._locked_contacts]
        sampled = random.sample(entries, min(nodes_num, len(entries)))
        return [entry.node for entry in sampled]

    def _get_staked_amount(self, address):
        now = self._clock.utcnow()
        if address in self._verified_nodes_db._nodes:
            staked = self._verified_nodes_db._nodes[address].staked_amount

    def get_available_staking_providers(self, exclude):
        now = self._clock.utcnow()
        entries = []
        for address, entry in self._verified_nodes_db._nodes.items():
            if address in self._staking_providers and self._staking_providers_updated > entry.verified_at:
                staked_amount = self._staking_providers[address]
            else:
                staked_amount = entry.staked_amount

            entries.append(StakingProviderEntry(
                address=address,
                contact=entry.node.secure_contact.contact,
                weight=int(staked_amount.as_ether())))

        for address, contacts in self._contacts_db._addresses_to_contacts.items():
            if address in self._staking_providers:
                staked_amount = self._staking_providers[address]
                for contact in contacts:
                    entries.append(StakingProviderEntry(
                        address=address,
                        contact=contact,
                        weight=int(staked_amount.as_ether() / len(contacts))))

        return entries

    @property
    def verified_node_entries(self):
        return self._verified_nodes_db._nodes

    def try_get_possible_contacts_for(self, address):
        contacts = self._contacts_db._addresses_to_contacts.get(address, [])
        return set(contacts) - self._locked_contacts.keys()

    def print_status(self):
        import io
        file = io.StringIO()
        print("Verified nodes:", file=file)
        for address, entry in self._verified_nodes_db._nodes.items():
            print(address, ":", entry, file=file)
        print(file=file)
        print("Verification queue:", file=file)
        for entry in self._verified_nodes_db._verify_at:
            print(entry, file=file)
        print(file=file)
        print("Contacts to addresses:", file=file)
        for contact, addresses in self._contacts_db._contacts_to_addresses.items():
            print(f"{contact}: {addresses}", file=file)
        print(file=file)
        print("Addresses to contacts:", file=file)
        for address, contacts in self._contacts_db._addresses_to_contacts.items():
            print(f"{address}: {contacts}", file=file)
        print(file=file)
        print("Locked contacts:", file=file)
        print(list(self._locked_contacts.keys()), file=file)
        return file.getvalue()
