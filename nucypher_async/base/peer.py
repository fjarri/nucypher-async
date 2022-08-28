"""
A peer interface is intentionally distantiated from an HTTP server,
to illustrate that it does not necessarily need to work via HTTP.
"""

from abc import ABC, abstractmethod
from enum import Enum, unique
import json
from typing import TypeVar, Type, Dict, Callable, Any, Optional

from nucypher_core import (
    MetadataRequest,
    MetadataResponse,
    NodeMetadata,
    ReencryptionRequest,
    ReencryptionResponse,
)
import trio

from ..utils.logging import Logger
from .types import JSON


@unique
class PeerErrorCode(Enum):
    GENERIC_ERROR = 0
    INVALID_MESSAGE = 1
    INACTIVE_POLICY = 2


class PeerError(Exception):
    pass


class UntypedPeerError(PeerError):
    pass


class ServerSidePeerError(ABC, PeerError):
    """
    A base class for errors that can be passed through whatever transport
    clients use to connect peers.
    """

    @staticmethod
    @abstractmethod
    def error_code() -> PeerErrorCode:
        """Mapping of this error class to a unique error code."""
        ...

    def to_json(self) -> Dict[str, JSON]:
        return dict(error=self.args[0], code=self.error_code())


def decode_peer_error(message: str) -> PeerError:
    try:
        parsed_message = json.loads(message)
    except json.decoder.JSONDecodeError:
        # Support for other implementation that just returns strings
        return UntypedPeerError(message)

    if not isinstance(parsed_message, dict):
        return UntypedPeerError(f"Peer error message is not a dictionary: {message}")

    try:
        code = parsed_message["code"]
    except KeyError:
        return UntypedPeerError(f"'code' is not set in the error dict: {message}")

    try:
        error = parsed_message["error"]
    except KeyError:
        return UntypedPeerError(f"'error' is not set in the error dict: {message}")

    try:
        code_obj = PeerErrorCode(code)
    except ValueError:
        return UntypedPeerError(f"Unknown peer error code {code}: {message}")

    try:
        cls = _PEER_ERROR_CODE_TO_CLASS[code_obj]
        return cls(error)
    except KeyError as exc:
        # Raising because this is not a peer error, this is a bug.
        # If the code is in the enum, there should be a class corresponding to it.
        raise ValueError(f"Unknown error class for {code}: {error}") from exc


class GenericPeerError(ServerSidePeerError):
    @staticmethod
    def error_code() -> PeerErrorCode:
        return PeerErrorCode.GENERIC_ERROR


class InvalidMessage(ServerSidePeerError):
    @staticmethod
    def error_code() -> PeerErrorCode:
        return PeerErrorCode.INVALID_MESSAGE

    @classmethod
    def for_message(cls, message_cls: Type[Any], exc: Exception) -> "InvalidMessage":
        return cls(f"Failed to parse {message_cls.__name__} bytes: {exc}")


class InactivePolicy(ServerSidePeerError):
    @staticmethod
    def error_code() -> PeerErrorCode:
        return PeerErrorCode.INACTIVE_POLICY


# For some reason without the annotation `mypy` complains when I try to instantiate the class
# take from this dict (because `ServerSidePeerError` is abstract), even though
# it infers the same return value by itself.
_PEER_ERROR_CODE_TO_CLASS: Dict[PeerErrorCode, Callable[[str], ServerSidePeerError]] = {
    cls.error_code(): cls
    for cls in [
        GenericPeerError,
        InvalidMessage,
        InactivePolicy,
    ]
}


class BasePeer(ABC):
    @abstractmethod
    async def start(self, nursery: trio.Nursery) -> None:
        ...

    @abstractmethod
    async def stop(self, nursery: trio.Nursery) -> None:
        ...

    @abstractmethod
    async def endpoint_ping(self, remote_host: Optional[str]) -> bytes:
        ...

    @abstractmethod
    async def node_metadata_get(self) -> MetadataResponse:
        ...

    async def endpoint_node_metadata_get(self) -> bytes:
        return bytes(await self.node_metadata_get())

    @abstractmethod
    async def node_metadata_post(
        self, remote_host: Optional[str], request: MetadataRequest
    ) -> MetadataResponse:
        ...

    async def endpoint_node_metadata_post(
        self, remote_host: Optional[str], request_bytes: bytes
    ) -> bytes:
        try:
            request = MetadataRequest.from_bytes(request_bytes)
        except ValueError as exc:
            raise InvalidMessage.for_message(MetadataRequest, exc) from exc
        return bytes(await self.node_metadata_post(remote_host, request))

    @abstractmethod
    async def public_information(self) -> NodeMetadata:
        ...

    async def endpoint_public_information(self) -> bytes:
        return bytes(await self.public_information())

    @abstractmethod
    async def reencrypt(self, request: ReencryptionRequest) -> ReencryptionResponse:
        ...

    async def endpoint_reencrypt(self, request_bytes: bytes) -> bytes:
        try:
            request = ReencryptionRequest.from_bytes(request_bytes)
        except ValueError as exc:
            raise InvalidMessage.for_message(ReencryptionRequest, exc) from exc

        return bytes(await self.reencrypt(request))

    # NOTE: This method really does not belong in the PeerAPI, because it is strictly HTTP,
    # while peers can theoretically use gRPC, or Noise, or something else.
    # But the way the protocol works now, it is hardcoded that the status page
    # should be available at the same port as the rest of the API, so it has to stay here.
    @abstractmethod
    async def endpoint_status(self) -> str:
        ...

    @abstractmethod
    def logger(self) -> Logger:
        ...
