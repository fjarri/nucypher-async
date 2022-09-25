from collections import defaultdict
from contextlib import contextmanager
import datetime
import io
import random
from functools import wraps
from typing import (
    Dict,
    List,
    AbstractSet,
    Tuple,
    Set,
    Iterable,
    Optional,
    TypeVar,
    Generic,
    Callable,
    Any,
    Iterator,
    cast,
)

from attrs import frozen, evolve
import arrow
from sortedcontainers import SortedKeyList
import trio
from typing_extensions import ParamSpec, Concatenate

from ..base.time import BaseClock
from ..drivers.identity import IdentityAddress, AmountT
from ..drivers.peer import Contact, UrsulaInfo
from .verification import PublicUrsula


@frozen
class NodeEntry:
    node: PublicUrsula
    verified_at: arrow.Arrow
    staked_amount: AmountT


@frozen
class VerifyAtEntry:
    address: IdentityAddress
    verify_at: arrow.Arrow


@frozen
class StakingProviderEntry:
    address: IdentityAddress
    contact: Contact
    weight: int


BroadcastValueT = TypeVar("BroadcastValueT")


class BroadcastValue(Generic[BroadcastValueT]):
    def __init__(self) -> None:
        self._value: Optional[BroadcastValueT] = None
        self._event = trio.Event()

    def set(self, value: BroadcastValueT) -> None:
        self._value = value
        self._event.set()

    async def wait(self) -> BroadcastValueT:
        await self._event.wait()
        # If the event was set, it's not None anymore
        return cast(BroadcastValueT, self._value)


class VerifiedNodesDB:
    def __init__(self) -> None:
        self._nodes: Dict[IdentityAddress, NodeEntry] = {}
        self._verify_at: SortedKeyList[VerifyAtEntry] = SortedKeyList(
            key=lambda entry: entry.verify_at
        )

    def add_node(
        self,
        node: PublicUrsula,
        staked_amount: AmountT,
        verified_at: arrow.Arrow,
        verify_at: arrow.Arrow,
    ) -> None:
        assert node.staking_provider_address not in self._nodes
        assert not any(entry.node.contact == node.contact for entry in self._nodes.values())
        self._nodes[node.staking_provider_address] = NodeEntry(
            node=node, verified_at=verified_at, staked_amount=staked_amount
        )
        self._verify_at.add(
            VerifyAtEntry(address=node.staking_provider_address, verify_at=verify_at)
        )

    def _del_verify_at(self, node: UrsulaInfo) -> None:
        # TODO: we really need a SortedDict type
        for i in range(len(self._verify_at)):
            if self._verify_at[i].address == node.staking_provider_address:
                del self._verify_at[i]
                break

    def get_verified_at(self, node: PublicUrsula) -> arrow.Arrow:
        return self._nodes[node.staking_provider_address].verified_at

    def update_verify_at(
        self, node: PublicUrsula, verified_at: arrow.Arrow, verify_at: arrow.Arrow
    ) -> None:
        assert node.staking_provider_address in self._nodes

        node_entry = evolve(self._nodes[node.staking_provider_address], verified_at=verified_at)
        self._nodes[node.staking_provider_address] = node_entry

        self._del_verify_at(node)
        self._verify_at.add(
            VerifyAtEntry(address=node.staking_provider_address, verify_at=verify_at)
        )

    def remove_node(self, node: UrsulaInfo) -> None:
        del self._nodes[node.staking_provider_address]
        self._del_verify_at(node)

    def remove_by_contact(self, contact: Contact) -> None:
        for address, entry in self._nodes.items():
            if entry.node.contact == contact:
                del self._nodes[address]
                self._del_verify_at(entry.node)
                break

    def all_nodes(self) -> List[PublicUrsula]:
        return [entry.node for entry in self._nodes.values()]

    def has_contact(self, contact: Contact) -> bool:
        return any(entry.node.contact == contact for entry in self._nodes.values())

    def is_empty(self) -> bool:
        return not bool(self._nodes)

    def next_verification_at(self, exclude: AbstractSet[Contact]) -> Optional[arrow.Arrow]:
        for entry in self._verify_at:
            if self._nodes[entry.address].node.contact not in exclude:
                return entry.verify_at
        return None

    def next_verification_in(
        self, now: arrow.Arrow, exclude: AbstractSet[Contact]
    ) -> Optional[datetime.timedelta]:
        time_point = self.next_verification_at(exclude)
        if time_point:
            return time_point - now if time_point > now else datetime.timedelta()
        return None

    def get_contacts_to_verify(
        self, now: arrow.Arrow, contacts_num: int, exclude: AbstractSet[Contact]
    ) -> List[Contact]:
        contacts: List[Contact] = []
        for entry in self._verify_at:
            if entry.verify_at > now:
                break

            contact = self._nodes[entry.address].node.contact
            if contact not in exclude:
                contacts.append(contact)

            if len(contacts) >= contacts_num:
                break

        return contacts


class ContactsDB:
    def __init__(self) -> None:
        self._contacts_to_addresses: Dict[Contact, Set[IdentityAddress]] = defaultdict(set)
        self._addresses_to_contacts: Dict[IdentityAddress, Set[Contact]] = defaultdict(set)

    def get_contacts_to_verify(
        self, contacts_num: int, exclude: AbstractSet[Contact]
    ) -> List[Contact]:
        contacts = list(self._contacts_to_addresses.keys() - exclude)

        # TODO: choose the contact that was supplied by the majority of nodes
        # This will help neutralize contact spam from malicious nodes.
        return random.sample(contacts, min(contacts_num, len(contacts)))

    def add_contact(self, contact: Contact, address: Optional[IdentityAddress] = None) -> None:
        if address is not None:
            self._contacts_to_addresses[contact].add(address)
            self._addresses_to_contacts[address].add(contact)
        else:
            self._contacts_to_addresses[contact].update()  # a no-op just to make the entry appear

    def remove_contact(self, contact: Contact) -> None:
        if contact in self._contacts_to_addresses:
            associated_addresses = self._contacts_to_addresses[contact]
            for address in associated_addresses:
                self._addresses_to_contacts[address].remove(contact)
                if len(self._addresses_to_contacts[address]) == 0:
                    del self._addresses_to_contacts[address]
            del self._contacts_to_addresses[contact]

    def remove_address(self, address: IdentityAddress) -> None:
        if address in self._addresses_to_contacts:
            associated_contacts = self._addresses_to_contacts[address]
            for contact in associated_contacts:
                self._contacts_to_addresses[contact].remove(address)
                # Not cleaning up empty entries from `_contacts_to_addresses`,
                # because a contact without a known address is still useful.
            del self._addresses_to_contacts[address]

    def is_empty(self) -> bool:
        return not bool(self._contacts_to_addresses)


Param = ParamSpec("Param")
RetVal = TypeVar("RetVal")


def _next_verification_time_may_change(
    func: Callable[Concatenate["FleetSensor", Param], RetVal]
) -> Callable[Concatenate["FleetSensor", Param], RetVal]:
    @wraps(func)
    def wrapped(
        fleet_sensor: "FleetSensor", /, *args: Param.args, **kwargs: Param.kwargs
    ) -> RetVal:

        contacts_present_before = not fleet_sensor._contacts_db.is_empty()
        next_verification_before = fleet_sensor._verified_nodes_db.next_verification_at(
            exclude=fleet_sensor._locked_contacts_for_verification.keys()
        )

        result = func(fleet_sensor, *args, **kwargs)

        contacts_present_after = not fleet_sensor._contacts_db.is_empty()
        next_verification_after = fleet_sensor._verified_nodes_db.next_verification_at(
            exclude=fleet_sensor._locked_contacts_for_verification.keys()
        )

        reschedule = (
            (contacts_present_after and not contacts_present_before)
            or (next_verification_before is None and next_verification_after is not None)
            or (
                next_verification_before is not None
                and next_verification_after is not None
                and next_verification_after < next_verification_before
            )
        )

        if reschedule:
            fleet_sensor.reschedule_verification_event.set()
            fleet_sensor.reschedule_verification_event = trio.Event()

        return result

    return wrapped


class FleetSensor:
    def __init__(
        self,
        clock: BaseClock,
        this_node: Optional[PublicUrsula],
    ):

        self._clock = clock

        self._my_staking_provider_address = (
            this_node.staking_provider_address if this_node else None
        )
        self._my_contact = this_node.contact if this_node else None

        self._verified_nodes_db = VerifiedNodesDB()
        self._contacts_db = ContactsDB()
        self._staking_providers: Dict[IdentityAddress, AmountT] = {}
        self._staking_providers_updated: Optional[arrow.Arrow] = None

        self._locked_contacts_for_learning: Dict[Contact, BroadcastValue[None]] = {}
        self._locked_contacts_for_verification: Dict[
            Contact, BroadcastValue[Optional[PublicUrsula]]
        ] = {}

        self.new_verified_nodes_event = trio.Event()
        self.reschedule_verification_event = trio.Event()

    def _calculate_next_verification(
        self,
        node: PublicUrsula,
        verified_at: arrow.Arrow,
        previously_verified_at: Optional[arrow.Arrow] = None,
    ) -> arrow.Arrow:

        if previously_verified_at:
            assert verified_at > previously_verified_at
            verify_at = (
                verified_at + (verified_at - previously_verified_at) * 1.5
            )  # TODO: remove hardcoding
        else:
            verify_at = verified_at.shift(hours=1)

        # If there's public key expiry incoming, verify then
        expires_at = node.public_key.not_valid_after
        verify_at = min(expires_at.shift(seconds=1), verify_at)

        # TODO: other limits for increasing the verification interval are possible.
        # How big is the unstaking timeout?

        assert verify_at > verified_at

        return verify_at

    @_next_verification_time_may_change
    def report_bad_contact(self, contact: Contact) -> None:
        self._contacts_db.remove_contact(contact)
        self._verified_nodes_db.remove_by_contact(contact)

    @_next_verification_time_may_change
    def report_verified_node(self, node: PublicUrsula, staked_amount: AmountT) -> None:

        if (
            self._my_staking_provider_address
            and node.staking_provider_address == self._my_staking_provider_address
        ):
            return

        verified_at = self._clock.utcnow()

        self._contacts_db.remove_contact(node.contact)
        self._contacts_db.remove_address(node.staking_provider_address)

        entry_by_staker = self._verified_nodes_db._nodes.get(node.staking_provider_address, None)

        if not entry_by_staker:
            # New verification

            # This contact may have had another staking provider associated with it,
            # unverify the old one
            # (if it is the same node, no harm done, we're doing _add_node() anyway).
            self._verified_nodes_db.remove_by_contact(node.contact)

            verify_at = self._calculate_next_verification(node, verified_at)
            self._add_node(node, staked_amount, verified_at, verify_at)

        else:
            # Re-verification
            old_node = entry_by_staker.node

            if bytes(node.metadata) == bytes(old_node.metadata):
                previously_verified_at = self._verified_nodes_db.get_verified_at(node)
                verify_at = self._calculate_next_verification(
                    node, verified_at, previously_verified_at
                )
                self._verified_nodes_db.update_verify_at(node, verified_at, verify_at)
            else:
                self._verified_nodes_db.remove_node(old_node)
                verify_at = self._calculate_next_verification(node, verified_at)
                self._add_node(node, staked_amount, verified_at, verify_at)

    @_next_verification_time_may_change
    def report_active_learning_results(
        self, teacher_node: UrsulaInfo, metadatas: Iterable[UrsulaInfo]
    ) -> None:
        for metadata in metadatas:
            if metadata.contact == teacher_node.contact and bytes(metadata) != bytes(teacher_node):
                self._verified_nodes_db.remove_node(teacher_node)
        self._add_contacts(metadatas)

    @_next_verification_time_may_change
    def report_passive_learning_results(
        self, sender_host: Optional[str], metadatas: Iterable[UrsulaInfo]
    ) -> None:

        # Filter out only the contact(s) with `remote_address`.
        # We're not going to trust all this metadata anyway.
        sender_metadatas = [
            metadata for metadata in metadatas if metadata.contact.host == sender_host
        ]
        self._add_contacts(sender_metadatas)

    @_next_verification_time_may_change
    def report_staking_providers(self, providers: Dict[IdentityAddress, AmountT]) -> None:
        self._staking_providers = providers
        self._staking_providers_updated = self._clock.utcnow()

    def verified_metadata(self) -> List[PublicUrsula]:
        return self._verified_nodes_db.all_nodes()

    def _add_node(
        self,
        node: PublicUrsula,
        staked_amount: AmountT,
        verified_at: arrow.Arrow,
        verify_at: arrow.Arrow,
    ) -> None:
        self._verified_nodes_db.add_node(node, staked_amount, verified_at, verify_at)
        self.new_verified_nodes_event.set()
        self.new_verified_nodes_event = trio.Event()

    def _add_contacts(self, metadatas: Iterable[UrsulaInfo]) -> None:
        for metadata in metadatas:
            contact = metadata.contact
            address = metadata.staking_provider_address

            if self._my_contact:
                if contact == self._my_contact or address == self._my_staking_provider_address:
                    continue

            if self._verified_nodes_db.has_contact(contact):
                continue

            self._contacts_db.add_contact(contact, address)

    def next_learning_in(self) -> float:
        # TODO: May be adjusted dynamically based on the network state
        return datetime.timedelta(seconds=90).total_seconds()

    def is_empty(self) -> bool:
        return self._contacts_db.is_empty() and self._verified_nodes_db.is_empty()

    def next_verification_in(self) -> float:

        if self._contacts_db.is_empty() and self._verified_nodes_db.is_empty():
            return datetime.timedelta.max.total_seconds()

        # If there are contacts to check, do it asap
        if not self._contacts_db.is_empty():
            return datetime.timedelta().total_seconds()

        now = self._clock.utcnow()
        next_verification_in = self._verified_nodes_db.next_verification_in(
            now, exclude=self._locked_contacts_for_verification.keys()
        )
        if next_verification_in is None:
            # Maybe someone will contact us during this time and leave some contacts.
            return datetime.timedelta(days=1).total_seconds()

        return next_verification_in.total_seconds()

    @contextmanager
    def try_lock_contact_for_learning(
        self, contact: Contact
    ) -> Iterator[Tuple[Optional[Contact], BroadcastValue[None]]]:
        if contact in self._locked_contacts_for_learning:
            yield None, self._locked_contacts_for_learning[contact]
            return

        bval: BroadcastValue[None] = BroadcastValue()
        self._locked_contacts_for_learning[contact] = bval
        try:
            yield contact, bval
        finally:
            del self._locked_contacts_for_learning[contact]

    @contextmanager
    def try_lock_contact_for_verification(
        self, contact: Contact
    ) -> Iterator[Tuple[Optional[Contact], BroadcastValue[Optional[PublicUrsula]]]]:
        if contact in self._locked_contacts_for_verification:
            yield None, self._locked_contacts_for_verification[contact]
            return

        bval: BroadcastValue[Optional[PublicUrsula]] = BroadcastValue()
        self._locked_contacts_for_verification[contact] = bval
        try:
            yield contact, bval
        finally:
            del self._locked_contacts_for_verification[contact]

    def get_contacts_to_verify(self, contacts_num: int) -> List[Contact]:
        return self._contacts_db.get_contacts_to_verify(
            contacts_num, exclude=self._locked_contacts_for_verification.keys()
        )

    def get_contacts_to_reverify(self, contacts_num: int) -> List[Contact]:
        now = self._clock.utcnow()
        return self._verified_nodes_db.get_contacts_to_verify(
            now, contacts_num, exclude=self._locked_contacts_for_verification.keys()
        )

    def get_nodes_to_learn_from(self, nodes_num: int) -> List[PublicUrsula]:
        entries = [
            entry
            for entry in self._verified_nodes_db._nodes.values()
            if entry.node.contact not in self._locked_contacts_for_learning
        ]
        sampled = random.sample(entries, min(nodes_num, len(entries)))
        return [entry.node for entry in sampled]

    def get_available_staking_providers(self) -> List[StakingProviderEntry]:
        entries = []
        for address, entry in self._verified_nodes_db._nodes.items():
            if (
                address in self._staking_providers
                and self._staking_providers_updated > entry.verified_at
            ):
                staked_amount = self._staking_providers[address]
            else:
                staked_amount = entry.staked_amount

            entries.append(
                StakingProviderEntry(
                    address=address,
                    contact=entry.node.contact,
                    weight=int(staked_amount.as_ether()),
                )
            )

        for address, contacts in self._contacts_db._addresses_to_contacts.items():
            if address in self._staking_providers:
                staked_amount = self._staking_providers[address]
                for contact in contacts:
                    entries.append(
                        StakingProviderEntry(
                            address=address,
                            contact=contact,
                            weight=int(staked_amount.as_ether() / len(contacts)),
                        )
                    )

        return entries

    @property
    def verified_node_entries(self) -> Dict[IdentityAddress, NodeEntry]:
        return self._verified_nodes_db._nodes

    def try_get_possible_contacts_for(self, address: IdentityAddress) -> Set[Contact]:
        contacts = self._contacts_db._addresses_to_contacts.get(address, set())
        return set(contacts) - self._locked_contacts_for_verification.keys()

    def print_status(self) -> str:
        file = io.StringIO()
        print("Verified nodes:", file=file)
        for address, node_entry in self._verified_nodes_db._nodes.items():
            print(address, ":", node_entry, file=file)
        print(file=file)
        print("Verification queue:", file=file)
        for verify_at_entry in self._verified_nodes_db._verify_at:
            print(verify_at_entry, file=file)
        print(file=file)
        print("Contacts to addresses:", file=file)
        for contact, addresses in self._contacts_db._contacts_to_addresses.items():
            print(f"{contact}: {addresses}", file=file)
        print(file=file)
        print("Addresses to contacts:", file=file)
        for address, contacts in self._contacts_db._addresses_to_contacts.items():
            print(f"{address}: {contacts}", file=file)
        print(file=file)
        print("Locked contacts for verification:", file=file)
        print(list(self._locked_contacts_for_verification.keys()), file=file)
        print(file=file)
        print("Locked contacts for learning:", file=file)
        print(list(self._locked_contacts_for_learning.keys()), file=file)
        return file.getvalue()
