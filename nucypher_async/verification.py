from nucypher_core import NodeMetadataPayload, NodeMetadata

from .base.peer import PeerError
from .base.time import BaseClock
from .drivers.identity import IdentityAddress, IdentityClientSession
from .drivers.peer import PeerInfo, Contact, SecureContact
from .domain import Domain
from .ursula import Ursula


class NodeVerificationError(PeerError):
    pass


async def _verify_staking_shared(session: IdentityClientSession, staking_provider_address: IdentityAddress, operator_address: IdentityAddress):
    if not await session.is_staking_provider_authorized(staking_provider_address):
        raise NodeVerificationError("Staking provider is not authorized")

    if not await session.is_operator_confirmed(operator_address):
        raise NodeVerificationError("Operator is not confirmed")


async def verify_staking_local(session: IdentityClientSession, operator_address: IdentityAddress):
    staking_provider_address = await session.get_staking_provider_address(operator_address)
    await _verify_staking_shared(session, staking_provider_address, operator_address)
    return staking_provider_address


async def verify_staking_remote(session: IdentityClientSession, staking_provider_address: IdentityAddress):
    operator_address = await session.get_operator_address(staking_provider_address)
    await _verify_staking_shared(session, staking_provider_address, operator_address)
    return operator_address


class PublicUrsula:

    @classmethod
    def checked_remote(cls, peer_info: PeerInfo, operator_address: IdentityAddress, domain: Domain) -> "PublicUrsula":

        payload = peer_info.metadata.payload

        if payload.domain != domain.value:
            raise NodeVerificationError(
                f"Domain mismatch: expected {domain}, {payload.domain} in the metadata")

        payload_operator_address = IdentityAddress(payload.derive_operator_address())
        if payload_operator_address != operator_address:
            raise NodeVerificationError(
                f"Invalid decentralized identity evidence: derived {payload_operator_address}, "
                f"but the bonded address is {operator_address}")

        return cls(peer_info)

    @classmethod
    def checked_local(cls, metadata: NodeMetadata, clock: BaseClock, ursula: Ursula,
            staking_provider_address: IdentityAddress, contact: Contact, domain: Domain) -> "PublicUrsula":

        peer_info = PeerInfo.checked_local(metadata, clock, ursula.peer_private_key(), contact)

        payload = peer_info.metadata.payload

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

        return cls(peer_info)

    @classmethod
    def generate(cls, clock: BaseClock, ursula: Ursula,
            staking_provider_address: IdentityAddress, contact: Contact, domain: Domain) -> "PublicUrsula":

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
        return cls(PeerInfo(metadata, secure_contact))

    def __init__(self, peer_info: PeerInfo):
        payload = peer_info.metadata.payload

        self.metadata = peer_info.metadata
        self.staking_provider_address = IdentityAddress(payload.staking_provider_address)
        self.operator_address = IdentityAddress(payload.derive_operator_address())
        self.verifying_key = payload.verifying_key
        self.encrypting_key = payload.encrypting_key
        self.domain = Domain.from_string(payload.domain)

        self.secure_contact = peer_info.secure_contact

    def __str__(self):
        return f"RemoteUrsula({self.staking_provider_address.checksum})"
