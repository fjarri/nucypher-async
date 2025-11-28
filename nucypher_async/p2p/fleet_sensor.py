import datetime
import io
import random
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator
from collections.abc import Set as AbstractSet
from contextlib import contextmanager
from functools import wraps
from typing import Concatenate, Generic, ParamSpec, TypeVar, cast

import arrow
import trio
from attrs import evolve, frozen
from sortedcontainers import SortedKeyList

from ..base.time import BaseClock
from ..drivers.identity import AmountT, IdentityAddress
from ..drivers.peer import Contact
from .node_info import NodeInfo
from .verification import VerifiedNodeInfo


@frozen
class NodeEntry:
    node: VerifiedNodeInfo
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


@frozen
class FleetSensorSnapshot:
    verified_node_entries: dict[IdentityAddress, NodeEntry]
    verify_at_entries: dict[IdentityAddress, VerifyAtEntry]
    addresses_to_contacts: dict[IdentityAddress, set[Contact]]
    staking_providers: dict[IdentityAddress, AmountT]


BroadcastValueT = TypeVar("BroadcastValueT")


class BroadcastValue(Generic[BroadcastValueT]):
    def __init__(self) -> None:
        self._value: BroadcastValueT | None = None
        self._event = trio.Event()

    def set(self, value: BroadcastValueT) -> None:
        self._value = value
        self._event.set()

    async def wait(self) -> BroadcastValueT:
        await self._event.wait()
        # If the event was set, it's not None anymore
        return cast("BroadcastValueT", self._value)


class VerifiedNodesDB:
    def __init__(self) -> None:
        self._nodes: dict[IdentityAddress, NodeEntry] = {}
        self._verify_at: SortedKeyList[VerifyAtEntry] = SortedKeyList(
            key=lambda entry: entry.verify_at
        )

    def add_node(
        self,
        node: VerifiedNodeInfo,
        staked_amount: AmountT,
        verified_at: arrow.Arrow,
        verify_at: arrow.Arrow,
    ) -> None:
        if node.staking_provider_address in self._nodes:
            raise ValueError(f"The address {node.staking_provider_address} is already added")

        if any(entry.node.contact == node.contact for entry in self._nodes.values()):
            raise ValueError(f"The contact {node.contact} is already added")

        self._nodes[node.staking_provider_address] = NodeEntry(
            node=node, verified_at=verified_at, staked_amount=staked_amount
        )
        self._verify_at.add(
            VerifyAtEntry(address=node.staking_provider_address, verify_at=verify_at)
        )

    def _del_verify_at(self, node: NodeInfo) -> None:
        # TODO: we really need a SortedDict type
        for i in range(len(self._verify_at)):
            if self._verify_at[i].address == node.staking_provider_address:
                del self._verify_at[i]
                break

    def get_verified_at(self, node: VerifiedNodeInfo) -> arrow.Arrow:
        return self._nodes[node.staking_provider_address].verified_at

    def update_verify_at(
        self, node: VerifiedNodeInfo, verified_at: arrow.Arrow, verify_at: arrow.Arrow
    ) -> None:
        if node.staking_provider_address not in self._nodes:
            raise ValueError(f"The address {node.staking_provider_address} is not a known node")

        node_entry = evolve(self._nodes[node.staking_provider_address], verified_at=verified_at)
        self._nodes[node.staking_provider_address] = node_entry

        self._del_verify_at(node)
        self._verify_at.add(
            VerifyAtEntry(address=node.staking_provider_address, verify_at=verify_at)
        )

    def remove_node(self, node: NodeInfo) -> None:
        del self._nodes[node.staking_provider_address]
        self._del_verify_at(node)

    def remove_by_contact(self, contact: Contact) -> None:
        for address, entry in self._nodes.items():
            if entry.node.contact == contact:
                del self._nodes[address]
                self._del_verify_at(entry.node)
                break

    def all_nodes(self) -> list[VerifiedNodeInfo]:
        return [entry.node for entry in self._nodes.values()]

    def has_contact(self, contact: Contact) -> bool:
        return any(entry.node.contact == contact for entry in self._nodes.values())

    def is_empty(self) -> bool:
        return not bool(self._nodes)

    def next_verification_at(self, exclude: AbstractSet[Contact]) -> arrow.Arrow | None:
        for entry in self._verify_at:
            if self._nodes[entry.address].node.contact not in exclude:
                return entry.verify_at
        return None

    def next_verification_in(
        self, now: arrow.Arrow, exclude: AbstractSet[Contact]
    ) -> datetime.timedelta | None:
        time_point = self.next_verification_at(exclude)
        if time_point:
            return time_point - now if time_point > now else datetime.timedelta()
        return None

    def get_contacts_to_verify(
        self, now: arrow.Arrow, contacts_num: int, exclude: AbstractSet[Contact]
    ) -> list[Contact]:
        contacts: list[Contact] = []
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
        self._contacts_to_addresses: dict[Contact, set[IdentityAddress]] = defaultdict(set)
        self._addresses_to_contacts: dict[IdentityAddress, set[Contact]] = defaultdict(set)

    def get_contacts_to_verify(
        self, contacts_num: int, exclude: AbstractSet[Contact]
    ) -> list[Contact]:
        contacts = list(self._contacts_to_addresses.keys() - exclude)

        # TODO: choose the contact that was supplied by the majority of nodes
        # This will help neutralize contact spam from malicious nodes.
        return random.sample(contacts, min(contacts_num, len(contacts)))

    def add_contact(self, contact: Contact, address: IdentityAddress | None = None) -> None:
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
    func: Callable[Concatenate["FleetSensor", Param], RetVal],
) -> Callable[Concatenate["FleetSensor", Param], RetVal]:
    @wraps(func)
    def wrapped(
        fleet_sensor: "FleetSensor", /, *args: Param.args, **kwargs: Param.kwargs
    ) -> RetVal:
        contacts_present_before = not fleet_sensor._contacts_db.is_empty()  # noqa: SLF001
        next_verification_before = fleet_sensor._verified_nodes_db.next_verification_at(  # noqa: SLF001
            exclude=fleet_sensor._locked_contacts_for_verification.keys()  # noqa: SLF001
        )

        result = func(fleet_sensor, *args, **kwargs)

        contacts_present_after = not fleet_sensor._contacts_db.is_empty()  # noqa: SLF001
        next_verification_after = fleet_sensor._verified_nodes_db.next_verification_at(  # noqa: SLF001
            exclude=fleet_sensor._locked_contacts_for_verification.keys()  # noqa: SLF001
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
        this_node: VerifiedNodeInfo | None,
    ):
        self._clock = clock

        self._this_node = this_node

        self._verified_nodes_db = VerifiedNodesDB()
        self._contacts_db = ContactsDB()
        self._staking_providers: dict[IdentityAddress, AmountT] = {}
        self._staking_providers_updated: arrow.Arrow | None = None

        self._locked_contacts_for_learning: dict[Contact, BroadcastValue[None]] = {}
        self._locked_contacts_for_verification: dict[
            Contact, BroadcastValue[VerifiedNodeInfo | None]
        ] = {}

        self.new_verified_nodes_event = trio.Event()
        self.reschedule_verification_event = trio.Event()

    def _calculate_next_verification(
        self,
        node: VerifiedNodeInfo,
        verified_at: arrow.Arrow,
        previously_verified_at: arrow.Arrow | None = None,
    ) -> arrow.Arrow:
        if previously_verified_at:
            # TODO: is this sanity check necessary? Can this really happen?
            # Note that this can be == in tests where we use `trio`'s mock clock.
            if verified_at < previously_verified_at:
                raise ValueError("`verified_at` must be after `previously_verified_at`")

            # Don't reverify too early
            previous_gap = max(verified_at - previously_verified_at, datetime.timedelta(hours=1))

            verify_at = verified_at + previous_gap * 1.5  # TODO: remove hardcoding of constants
        else:
            verify_at = verified_at.shift(hours=1)

        # If there's public key expiry incoming, verify then
        expires_at = node.public_key.not_valid_after
        verify_at = min(expires_at.shift(seconds=1), verify_at)

        # TODO: other limits for increasing the verification interval are possible.
        # How big is the unstaking timeout?

        # TODO: can this ever happen given the algorithm above?
        if verify_at <= verified_at:
            raise RuntimeError(
                "The planned verification time is prior to the existing verification"
            )

        return verify_at

    @_next_verification_time_may_change
    def report_bad_contact(self, contact: Contact) -> None:
        self._contacts_db.remove_contact(contact)
        self._verified_nodes_db.remove_by_contact(contact)

    @_next_verification_time_may_change
    def report_verified_node(self, node: VerifiedNodeInfo, staked_amount: AmountT) -> None:
        if (
            self._this_node is not None
            and node.staking_provider_address == self._this_node.staking_provider_address
        ):
            return

        verified_at = self._clock.utcnow()

        self._contacts_db.remove_contact(node.contact)
        self._contacts_db.remove_address(node.staking_provider_address)

        entry_by_staker = self._verified_nodes_db._nodes.get(node.staking_provider_address, None)  # noqa: SLF001

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
        self, teacher_node: NodeInfo, metadatas: Iterable[NodeInfo]
    ) -> None:
        for metadata in metadatas:
            if metadata.contact == teacher_node.contact and bytes(metadata) != bytes(teacher_node):
                self._verified_nodes_db.remove_node(teacher_node)
        self._add_contacts(metadatas)

    @_next_verification_time_may_change
    def report_passive_learning_results(
        self, sender_host: str | None, metadatas: Iterable[NodeInfo]
    ) -> None:
        # Filter out only the contact(s) with `remote_address`.
        # We're not going to trust all this metadata anyway.
        sender_metadatas = [
            metadata for metadata in metadatas if metadata.contact.host == sender_host
        ]
        self._add_contacts(sender_metadatas)

    @_next_verification_time_may_change
    def report_staking_providers(self, providers: dict[IdentityAddress, AmountT]) -> None:
        self._staking_providers = providers
        self._staking_providers_updated = self._clock.utcnow()

    def verified_metadata(self) -> list[VerifiedNodeInfo]:
        return self._verified_nodes_db.all_nodes() + (
            [self._this_node] if self._this_node is not None else []
        )

    def _add_node(
        self,
        node: VerifiedNodeInfo,
        staked_amount: AmountT,
        verified_at: arrow.Arrow,
        verify_at: arrow.Arrow,
    ) -> None:
        self._verified_nodes_db.add_node(node, staked_amount, verified_at, verify_at)
        self.new_verified_nodes_event.set()
        self.new_verified_nodes_event = trio.Event()

    def _add_contacts(self, metadatas: Iterable[NodeInfo]) -> None:
        for metadata in metadatas:
            contact = metadata.contact
            address = metadata.staking_provider_address

            if self._this_node is not None and (
                contact == self._this_node.contact
                or address == self._this_node.staking_provider_address
            ):
                continue

            if self._verified_nodes_db.has_contact(contact):
                continue

            self._contacts_db.add_contact(contact, address)

    # TODO: return the `timedelta` object instead.
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
    ) -> Iterator[tuple[Contact | None, BroadcastValue[None]]]:
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
    ) -> Iterator[tuple[Contact | None, BroadcastValue[VerifiedNodeInfo | None]]]:
        if contact in self._locked_contacts_for_verification:
            yield None, self._locked_contacts_for_verification[contact]
            return

        bval: BroadcastValue[VerifiedNodeInfo | None] = BroadcastValue()
        self._locked_contacts_for_verification[contact] = bval
        try:
            yield contact, bval
        finally:
            del self._locked_contacts_for_verification[contact]

    def get_contacts_to_verify(self, contacts_num: int) -> list[Contact]:
        return self._contacts_db.get_contacts_to_verify(
            contacts_num, exclude=self._locked_contacts_for_verification.keys()
        )

    def get_contacts_to_reverify(self, contacts_num: int) -> list[Contact]:
        now = self._clock.utcnow()
        return self._verified_nodes_db.get_contacts_to_verify(
            now, contacts_num, exclude=self._locked_contacts_for_verification.keys()
        )

    def get_nodes_to_learn_from(self, nodes_num: int) -> list[VerifiedNodeInfo]:
        entries = [
            entry
            for entry in self._verified_nodes_db._nodes.values()  # noqa: SLF001
            if entry.node.contact not in self._locked_contacts_for_learning
        ]
        sampled = random.sample(entries, min(nodes_num, len(entries)))
        return [entry.node for entry in sampled]

    def get_available_staking_providers(self) -> list[StakingProviderEntry]:
        # TODO: update this list as we verify nodes, so that we could just return it on call -
        # Porter needs this to reduce its response time.
        entries = []
        for address, entry in self._verified_nodes_db._nodes.items():  # noqa: SLF001
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

        for address, contacts in self._contacts_db._addresses_to_contacts.items():  # noqa: SLF001
            if address in self._staking_providers:
                staked_amount = self._staking_providers[address]
                entries.extend(
                    StakingProviderEntry(
                        address=address,
                        contact=contact,
                        weight=int(staked_amount.as_ether() / len(contacts)),
                    )
                    for contact in contacts
                )

        return entries

    @property
    def verified_node_entries(self) -> dict[IdentityAddress, NodeEntry]:
        return self._verified_nodes_db._nodes  # noqa: SLF001

    def try_get_possible_contacts_for(self, address: IdentityAddress) -> set[Contact]:
        contacts = self._contacts_db._addresses_to_contacts.get(address, set())  # noqa: SLF001
        return set(contacts) - self._locked_contacts_for_verification.keys()

    def print_status(self) -> str:
        file = io.StringIO()
        print("Verified nodes:", file=file)
        for address, node_entry in self._verified_nodes_db._nodes.items():  # noqa: SLF001
            print(address, ":", node_entry, file=file)
        print(file=file)
        print("Verification queue:", file=file)
        for verify_at_entry in self._verified_nodes_db._verify_at:  # noqa: SLF001
            print(verify_at_entry, file=file)
        print(file=file)
        print("Contacts to addresses:", file=file)
        for contact, addresses in self._contacts_db._contacts_to_addresses.items():  # noqa: SLF001
            print(f"{contact}: {addresses}", file=file)
        print(file=file)
        print("Addresses to contacts:", file=file)
        for address, contacts in self._contacts_db._addresses_to_contacts.items():  # noqa: SLF001
            print(f"{address}: {contacts}", file=file)
        print(file=file)
        print("Locked contacts for verification:", file=file)
        print(list(self._locked_contacts_for_verification.keys()), file=file)
        print(file=file)
        print("Locked contacts for learning:", file=file)
        print(list(self._locked_contacts_for_learning.keys()), file=file)
        return file.getvalue()

    def get_snapshot(self) -> FleetSensorSnapshot:
        return FleetSensorSnapshot(
            verified_node_entries=dict(self._verified_nodes_db._nodes),  # noqa: SLF001
            verify_at_entries={
                entry.address: entry
                for entry in self._verified_nodes_db._verify_at  # noqa: SLF001
            },
            addresses_to_contacts=dict(self._contacts_db._addresses_to_contacts),  # noqa: SLF001
            staking_providers=dict(self._staking_providers),
        )
