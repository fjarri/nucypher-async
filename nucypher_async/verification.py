from nucypher_core import NodeMetadataPayload, NodeMetadata

from .base import PeerError
from .drivers.identity import IdentityAddress
from .drivers.peer import Peer, SecureContact
from .domain import Domain


class NodeVerificationError(PeerError):
    pass


async def _verify_staking_shared(session, staking_provider_address, operator_address):
    if not await session.is_staking_provider_authorized(staking_provider_address):
        raise NodeVerificationError("Staking provider is not authorized")

    if not await session.is_operator_confirmed(operator_address):
        raise NodeVerificationError("Operator is not confirmed")


async def verify_staking_local(session, operator_address):
    staking_provider_address = await session.get_staking_provider_address(operator_address)
    await _verify_staking_shared(session, staking_provider_address, operator_address)
    return staking_provider_address


async def verify_staking_remote(session, staking_provider_address):
    operator_address = await session.get_operator_address(staking_provider_address)
    await _verify_staking_shared(session, staking_provider_address, operator_address)
    return operator_address


class PublicUrsula:

    @classmethod
    def checked_remote(cls, peer, operator_address, domain):

        payload = peer.metadata.payload

        if payload.domain != domain.value:
            raise NodeVerificationError(
                f"Domain mismatch: expected {domain}, {payload.domain} in the metadata")

        payload_operator_address = IdentityAddress(payload.derive_operator_address())
        if payload_operator_address != operator_address:
            raise NodeVerificationError(
                f"Invalid decentralized identity evidence: derived {peer.operator_address}, "
                f"but the bonded address is {operator_address}")

        return cls(peer)

    @classmethod
    def checked_local(cls, metadata, clock, ursula, staking_provider_address, contact, domain):
        peer = Peer.checked_local(metadata, clock, ursula.peer_private_key(), contact)

        payload = peer.metadata.payload

        if payload.domain != domain.value:
            raise NodeVerificationError(
                f"Domain mismatch: expected {domain}, {payload.domain} in the metadata")

        payload_staking_provider_address = IdentityAddress(payload.staking_provider_address)
        if payload_staking_provider_address != staking_provider_address:
            raise NodeVerificationError(
                f"Staking provider address mismatch: {payload_staking_provider_address} in the metadata, "
                f"{staking_provider_address} recorded in the blockchain")

        payload_operator_address = IdentityAddress(payload.derive_operator_address())
        if payload_operator_address != ursula.operator_address:
            raise NodeVerificationError(
                f"Operator address mismatch: {payload_operator_address} derived from the metadata, "
                f"{ursula.operator_address} supplied on start")

        if payload.verifying_key != ursula.signer.verifying_key():
            raise NodeVerificationError(
                f"Verifying key mismatch: {payload.verifying_key} in the metadata, "
                f"{ursula.signer.verifying_key()} derived from the master key")

        if payload.encrypting_key != ursula.encrypting_key:
            raise NodeVerificationError(
                f"Encrypting key mismatch: {payload.encrypting_key} in the metadata, "
                f"{ursula.encrypting_key} derived from the master key")

        return cls(peer)

    @classmethod
    def generate(cls, clock, ursula, staking_provider_address, contact, domain):

        secure_contact = SecureContact.generate(ursula.peer_private_key(), clock, contact)

        payload = NodeMetadataPayload(staking_provider_address=bytes(staking_provider_address),
                                      domain=domain.value,
                                      timestamp_epoch=int(clock.utcnow().timestamp()),
                                      operator_signature=ursula.operator_signature,
                                      verifying_key=ursula.signer.verifying_key(),
                                      encrypting_key=ursula.encrypting_key,
                                      # Abstraction leak here, ideally NodeMetadata should
                                      # have a field like `peer_public_key`.
                                      certificate_der=bytes(secure_contact.public_key),
                                      host=contact.host,
                                      port=contact.port,
                                      )
        metadata = NodeMetadata(signer=ursula.signer, payload=payload)
        return cls(Peer(metadata, secure_contact))

    def __init__(self, peer):
        payload = peer.metadata.payload

        self.metadata = peer.metadata
        self.staking_provider_address = IdentityAddress(payload.staking_provider_address)
        self.operator_address = IdentityAddress(payload.derive_operator_address())
        self.verifying_key = payload.verifying_key
        self.encrypting_key = payload.encrypting_key
        self.domain = Domain.from_string(payload.domain)

        self.secure_contact = peer.secure_contact

    def __str__(self):
        return f"RemoteUrsula({self.staking_provider_address.checksum})"
