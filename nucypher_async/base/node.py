from abc import ABC, abstractmethod

import trio
from nucypher_core import (
    EncryptedThresholdDecryptionRequest,
    EncryptedThresholdDecryptionResponse,
    MetadataRequest,
    MetadataResponse,
    NodeMetadata,
    ReencryptionRequest,
    ReencryptionResponse,
)

from ..utils.logging import Logger
from .peer_error import InvalidMessage
from .types import JSON


class NodeRoutes:
    NODE_METADATA = "node_metadata"
    PUBLIC_INFORMATION = "public_information"
    PING = "ping"
    REENCRYPT = "reencrypt"
    CONDITION_CHAINS = "condition_chains"
    DECRYPT = "decrypt"
    STATUS = "status"


class BaseNodeServer(ABC):
    @abstractmethod
    async def start(self, nursery: trio.Nursery) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def endpoint_ping(self, remote_host: str | None) -> bytes: ...

    @abstractmethod
    async def node_metadata(
        self, remote_host: str | None, request: MetadataRequest
    ) -> MetadataResponse: ...

    async def endpoint_node_metadata(self, remote_host: str | None, request_bytes: bytes) -> bytes:
        try:
            request = MetadataRequest.from_bytes(request_bytes)
        except ValueError as exc:
            raise InvalidMessage.for_message(MetadataRequest, exc) from exc
        return bytes(await self.node_metadata(remote_host, request))

    @abstractmethod
    async def public_information(self) -> NodeMetadata: ...

    async def endpoint_public_information(self) -> bytes:
        return bytes(await self.public_information())

    @abstractmethod
    async def reencrypt(self, request: ReencryptionRequest) -> ReencryptionResponse: ...

    async def endpoint_reencrypt(self, request_bytes: bytes) -> bytes:
        try:
            request = ReencryptionRequest.from_bytes(request_bytes)
        except ValueError as exc:
            raise InvalidMessage.for_message(ReencryptionRequest, exc) from exc

        return bytes(await self.reencrypt(request))

    @abstractmethod
    async def endpoint_condition_chains(self) -> JSON: ...

    @abstractmethod
    async def decrypt(
        self, request: EncryptedThresholdDecryptionRequest
    ) -> EncryptedThresholdDecryptionResponse: ...

    async def endpoint_decrypt(self, request_bytes: bytes) -> bytes:
        try:
            request = EncryptedThresholdDecryptionRequest.from_bytes(request_bytes)
        except ValueError as exc:
            raise InvalidMessage.for_message(EncryptedThresholdDecryptionRequest, exc) from exc

        return bytes(await self.decrypt(request))

    # NOTE: This method really does not belong in the PeerAPI, because it is strictly HTTP,
    # while peers can theoretically use gRPC, or Noise, or something else.
    # But the way the protocol works now, it is hardcoded that the status page
    # should be available at the same port as the rest of the API, so it has to stay here.
    @abstractmethod
    async def endpoint_status(self) -> str: ...

    @abstractmethod
    def logger(self) -> Logger: ...
