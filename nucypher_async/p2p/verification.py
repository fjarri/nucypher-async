from nucypher_core import Address, NodeMetadata, NodeMetadataPayload
from nucypher_core.ferveo import FerveoPublicKey
from nucypher_core.umbral import PublicKey, RecoverableSignature, Signer

from ..base.time import BaseClock
from ..characters.pre import Ursula
from ..domain import Domain
from ..drivers.identity import IdentityAddress, IdentityClientSession
from ..drivers.peer import Contact, PeerError, PeerPrivateKey, PeerPublicKey, SecureContact
from .ursula import UrsulaInfo


class PeerVerificationError(PeerError):
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
    ursula_info: UrsulaInfo,
    expected_contact: Contact,
    expected_domain: Domain,
    expected_operator_address: IdentityAddress,
) -> None:
    if ursula_info.contact != expected_contact:
        raise PeerVerificationError(
            f"Contact info mismatch: expected {expected_contact}, "
            f"{ursula_info.contact} in the metadata"
        )

    if ursula_info.operator_address != expected_operator_address:
        raise PeerVerificationError(
            f"Invalid decentralized identity evidence: derived {ursula_info.operator_address}, "
            f"but the bonded address is {expected_operator_address}"
        )

    now = clock.utcnow()

    if now < ursula_info.public_key.not_valid_before:
        raise PeerVerificationError(
            f"Peer public key will only become active at {ursula_info.public_key.not_valid_before}"
        )

    if now > ursula_info.public_key.not_valid_after:
        raise PeerVerificationError(
            f"Peer public key expired at {ursula_info.public_key.not_valid_after}"
        )

    if ursula_info.domain != expected_domain:
        raise PeerVerificationError(
            f"Domain mismatch: expected {expected_domain}, {ursula_info.domain} in the metadata"
        )


class VerifiedUrsulaInfo(UrsulaInfo):
    @classmethod
    def generate(
        cls,
        peer_private_key: PeerPrivateKey,
        peer_public_key: PeerPublicKey | None,
        signer: Signer,
        encrypting_key: PublicKey,
        dkg_key: FerveoPublicKey,
        operator_signature: RecoverableSignature,
        clock: BaseClock,
        staking_provider_address: IdentityAddress,
        contact: Contact,
        domain: Domain,
    ) -> "VerifiedUrsulaInfo":
        # TODO: use Ursula instead of several arguments
        public_key = peer_public_key or PeerPublicKey.generate(peer_private_key, clock, contact)
        payload = NodeMetadataPayload(
            staking_provider_address=Address(bytes(staking_provider_address)),
            domain=domain.value,
            timestamp_epoch=int(clock.utcnow().timestamp()),
            operator_signature=operator_signature,
            verifying_key=signer.verifying_key(),
            encrypting_key=encrypting_key,
            ferveo_public_key=dkg_key,
            # Abstraction leak here, ideally NodeMetadata should
            # have a field like `peer_public_key`.
            certificate_der=bytes(public_key),
            host=contact.host,
            port=contact.port,
        )
        metadata = NodeMetadata(signer=signer, payload=payload)
        return cls(metadata)

    @classmethod
    def checked_remote(
        cls,
        clock: BaseClock,
        ursula_info: UrsulaInfo,
        received_from: SecureContact,
        operator_address: IdentityAddress,
        domain: Domain,
    ) -> "VerifiedUrsulaInfo":
        _verify_peer_shared(
            clock=clock,
            ursula_info=ursula_info,
            expected_contact=received_from.contact,
            expected_domain=domain,
            expected_operator_address=operator_address,
        )

        if ursula_info.public_key != received_from.public_key:
            raise PeerVerificationError(
                "Peer public key mismatch between the payload and the contact it was received from"
            )

        return cls(ursula_info.metadata)

    @classmethod
    def checked_local(
        cls,
        clock: BaseClock,
        ursula_info: UrsulaInfo,
        ursula: Ursula,
        staking_provider_address: IdentityAddress,
        contact: Contact,
        domain: Domain,
        peer_private_key: PeerPrivateKey,
        peer_public_key: PeerPublicKey | None,
    ) -> "VerifiedUrsulaInfo":
        _verify_peer_shared(
            clock=clock,
            ursula_info=ursula_info,
            expected_contact=contact,
            expected_domain=domain,
            expected_operator_address=ursula.operator_address,
        )

        if not peer_private_key.matches(ursula_info.public_key):
            raise PeerVerificationError(
                "The peer public key in the metadata does not match the given peer private key"
            )

        if peer_public_key is not None and peer_public_key != ursula_info.public_key:
            raise PeerVerificationError(
                "The peer public key in the metadata does not match the given peer public key"
            )

        # TODO: check that peer_public_key.host == contact.host? Or is that redundant at this point?

        if ursula_info.staking_provider_address != staking_provider_address:
            raise PeerVerificationError(
                "Staking provider address mismatch: "
                f"{ursula_info.staking_provider_address} in the metadata, "
                f"{staking_provider_address} recorded in the blockchain"
            )

        if ursula_info.verifying_key != ursula.signer.verifying_key():
            raise PeerVerificationError(
                f"Verifying key mismatch: {ursula_info.verifying_key} in the metadata, "
                f"{ursula.signer.verifying_key()} derived from the master key"
            )

        if ursula_info.encrypting_key != ursula.encrypting_key:
            raise PeerVerificationError(
                f"Encrypting key mismatch: {ursula_info.encrypting_key} in the metadata, "
                f"{ursula.encrypting_key} derived from the master key"
            )

        return cls(ursula_info.metadata)

    def __str__(self) -> str:
        return f"RemoteUrsula({self.staking_provider_address.checksum})"
