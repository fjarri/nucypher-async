from nucypher_core import Address, NodeMetadata, NodeMetadataPayload

from .._drivers.time import BaseClock
from ..blockchain.identity import IdentityAddress, IdentityClientSession
from ..characters.cbd import DkgNodeCard
from ..characters.pre import ReencryptorCard
from ..domain import Domain
from ._keys import Contact, PeerPublicKey, SecureContact
from ._node_info import NodeInfo
from ._operator import Operator


class PeerVerificationError(Exception):
    pass


async def _verify_staking_shared(
    session: IdentityClientSession,
    staking_provider_address: IdentityAddress,
    operator_address: IdentityAddress,
) -> None:
    if not await session.is_staking_provider_authorized(staking_provider_address):
        raise PeerVerificationError("Staking provider is not authorized")

    if not await session.is_operator_confirmed(operator_address):
        raise PeerVerificationError("Operator is not confirmed")


async def verify_staking_local(
    session: IdentityClientSession, operator_address: IdentityAddress
) -> IdentityAddress:
    staking_provider_address = await session.get_staking_provider_address(operator_address)
    await _verify_staking_shared(session, staking_provider_address, operator_address)
    return staking_provider_address


async def verify_staking_remote(
    session: IdentityClientSession, staking_provider_address: IdentityAddress
) -> IdentityAddress:
    operator_address = await session.get_operator_address(staking_provider_address)
    await _verify_staking_shared(session, staking_provider_address, operator_address)
    return operator_address


def _verify_peer_shared(
    clock: BaseClock,
    node_info: NodeInfo,
    expected_contact: Contact,
    expected_domain: Domain,
    expected_operator_address: IdentityAddress,
) -> None:
    if node_info.contact != expected_contact:
        raise PeerVerificationError(
            f"Contact info mismatch: expected {expected_contact}, "
            f"{node_info.contact} in the metadata"
        )

    if node_info.operator_address != expected_operator_address:
        raise PeerVerificationError(
            f"Invalid decentralized identity evidence: derived {node_info.operator_address}, "
            f"but the bonded address is {expected_operator_address}"
        )

    now = clock.utcnow()

    if now < node_info.public_key.not_valid_before:
        raise PeerVerificationError(
            f"Peer public key will only become active at {node_info.public_key.not_valid_before}"
        )

    if now > node_info.public_key.not_valid_after:
        raise PeerVerificationError(
            f"Peer public key expired at {node_info.public_key.not_valid_after}"
        )

    if node_info.domain != expected_domain:
        raise PeerVerificationError(
            f"Domain mismatch: expected {expected_domain}, {node_info.domain} in the metadata"
        )


class VerifiedNodeInfo(NodeInfo):
    @classmethod
    def generate(
        cls,
        operator: Operator,
        peer_public_key: PeerPublicKey | None,
        reencryptor_card: ReencryptorCard,
        dkg_node_card: DkgNodeCard,
        clock: BaseClock,
        staking_provider_address: IdentityAddress,
        contact: Contact,
        domain: Domain,
    ) -> "VerifiedNodeInfo":
        public_key = peer_public_key or PeerPublicKey.generate(
            operator.peer_private_key, clock, contact
        )
        payload = NodeMetadataPayload(
            staking_provider_address=Address(bytes(staking_provider_address)),
            domain=domain.value,
            timestamp_epoch=int(clock.utcnow().timestamp()),
            operator_signature=operator.signature,
            verifying_key=operator.verifying_key,
            encrypting_key=reencryptor_card.encrypting_key,
            ferveo_public_key=dkg_node_card.public_key,
            # Abstraction leak here, ideally NodeMetadata should
            # have a field like `transport_public_key`.
            certificate_der=bytes(public_key),
            host=str(contact.host),
            port=contact.port,
        )
        metadata = NodeMetadata(signer=operator.signer, payload=payload)
        return cls(metadata)

    @classmethod
    def checked_remote(
        cls,
        clock: BaseClock,
        node_info: NodeInfo,
        received_from: SecureContact,
        operator_address: IdentityAddress,
        domain: Domain,
    ) -> "VerifiedNodeInfo":
        _verify_peer_shared(
            clock=clock,
            node_info=node_info,
            expected_contact=received_from.contact,
            expected_domain=domain,
            expected_operator_address=operator_address,
        )

        if node_info.public_key != received_from.public_key:
            raise PeerVerificationError(
                "Peer public key mismatch between the payload and the contact it was received from"
            )

        return cls(node_info.metadata)

    @classmethod
    def checked_local(
        cls,
        clock: BaseClock,
        node_info: NodeInfo,
        operator: Operator,
        reencryptor_card: ReencryptorCard,
        staking_provider_address: IdentityAddress,
        contact: Contact,
        domain: Domain,
        peer_public_key: PeerPublicKey | None,
    ) -> "VerifiedNodeInfo":
        _verify_peer_shared(
            clock=clock,
            node_info=node_info,
            expected_contact=contact,
            expected_domain=domain,
            expected_operator_address=operator.address,
        )

        if not operator.peer_private_key.matches(node_info.public_key):
            raise PeerVerificationError(
                "The peer public key in the metadata does not match the given peer private key"
            )

        if peer_public_key is not None and peer_public_key != node_info.public_key:
            raise PeerVerificationError(
                "The peer public key in the metadata does not match the given peer public key"
            )

        if peer_public_key is not None and peer_public_key.declared_host != contact.host:
            raise PeerVerificationError(
                f"The host declared in the public key ({peer_public_key.declared_host}) "
                f"is different from the external host in the config ({contact.host})"
            )

        if node_info.staking_provider_address != staking_provider_address:
            raise PeerVerificationError(
                "Staking provider address mismatch: "
                f"{node_info.staking_provider_address} in the metadata, "
                f"{staking_provider_address} recorded in the blockchain"
            )

        if node_info.pre_verifying_key != operator.verifying_key:
            raise PeerVerificationError(
                f"Verifying key mismatch: {node_info.pre_verifying_key} in the metadata, "
                f"{operator.verifying_key} derived from the master key"
            )

        if node_info.pre_encrypting_key != reencryptor_card.encrypting_key:
            raise PeerVerificationError(
                f"Encrypting key mismatch: {node_info.pre_encrypting_key} in the metadata, "
                f"{reencryptor_card.encrypting_key} derived from the master key"
            )

        return cls(node_info.metadata)

    def reencryptor_card(self) -> ReencryptorCard:
        return ReencryptorCard(encrypting_key=self.pre_encrypting_key)

    def __str__(self) -> str:
        return f"VerifiedNodeInfo({self.staking_provider_address.checksum})"
