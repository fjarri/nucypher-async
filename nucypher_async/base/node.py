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
    def logger(self) -> Logger: ...

    @abstractmethod
    async def start(self, nursery: trio.Nursery) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def ping(self, remote_host: str | None) -> str: ...

    @abstractmethod
    async def node_metadata(
        self, remote_host: str | None, request: MetadataRequest
    ) -> MetadataResponse: ...

    @abstractmethod
    async def public_information(self) -> NodeMetadata: ...

    @abstractmethod
    async def reencrypt(self, request: ReencryptionRequest) -> ReencryptionResponse: ...

    @abstractmethod
    async def condition_chains(self) -> JSON: ...

    @abstractmethod
    async def decrypt(
        self, request: EncryptedThresholdDecryptionRequest
    ) -> EncryptedThresholdDecryptionResponse: ...

    # NOTE: This method really does not belong in the PeerAPI, because it is strictly HTTP,
    # while peers can theoretically use gRPC, or Noise, or something else.
    # But the way the protocol works now, it is hardcoded that the status page
    # should be available at the same port as the rest of the API, so it has to stay here.
    @abstractmethod
    async def status(self) -> str: ...
