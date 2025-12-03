"""
A peer interface is intentionally distantiated from an HTTP server,
to illustrate that it does not necessarily need to work via HTTP.
"""

import json
from abc import ABC, abstractmethod
from collections.abc import Callable
from enum import Enum, unique
from typing import Any

from ..base.types import JSON


@unique
class PeerErrorCode(Enum):
    GENERIC_ERROR = 0
    INVALID_MESSAGE = 1
    INACTIVE_POLICY = 2


class PeerError(Exception):
    @staticmethod
    def from_json(encoded_json: bytes) -> "PeerError":
        # This method is separate from `ServerSidePeerError.to_json` because the result
        # is not necessarily a `ServerSidePeerError` - we can get `UntypedPeerError` too,
        # if the error message is malformed.
        try:
            parsed_message = json.loads(encoded_json)
        except json.decoder.JSONDecodeError:
            # Support for other implementation that just returns strings
            return UntypedPeerError(encoded_json)

        if not isinstance(parsed_message, dict):
            return UntypedPeerError(f"Peer error message is not a dictionary: {parsed_message}")

        try:
            code = parsed_message["code"]
        except KeyError:
            return UntypedPeerError(f"'code' is not set in the error dict: {parsed_message}")

        try:
            error = parsed_message["error"]
        except KeyError:
            return UntypedPeerError(f"'error' is not set in the error dict: {parsed_message}")

        try:
            code_obj = PeerErrorCode(code)
        except ValueError:
            return UntypedPeerError(f"Unknown peer error code {code}: {parsed_message}")

        try:
            cls = _PEER_ERROR_CODE_TO_CLASS[code_obj]
            return cls(error)
        except KeyError as exc:
            # Raising because this is not a peer error, this is a bug.
            # If the code is in the enum, there should be a class corresponding to it.
            raise ValueError(f"Unknown error class for {code}: {error}") from exc


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

    def to_json(self) -> dict[str, JSON]:
        return dict(error=self.args[0], code=self.error_code().value)


class GenericPeerError(ServerSidePeerError):
    @staticmethod
    def error_code() -> PeerErrorCode:
        return PeerErrorCode.GENERIC_ERROR


class InvalidMessage(ServerSidePeerError):
    @staticmethod
    def error_code() -> PeerErrorCode:
        return PeerErrorCode.INVALID_MESSAGE

    @classmethod
    def for_message(cls, message_cls: type[Any], exc: Exception) -> "InvalidMessage":
        return cls(f"Failed to parse {message_cls.__name__} bytes: {exc}")


class InactivePolicy(ServerSidePeerError):
    @staticmethod
    def error_code() -> PeerErrorCode:
        return PeerErrorCode.INACTIVE_POLICY


# For some reason without the annotation `mypy` complains when I try to instantiate the class
# take from this dict (because `ServerSidePeerError` is abstract), even though
# it infers the same return value by itself.
_PEER_ERROR_CODE_TO_CLASS: dict[PeerErrorCode, Callable[[str], ServerSidePeerError]] = {
    cls.error_code(): cls
    for cls in [
        GenericPeerError,
        InvalidMessage,
        InactivePolicy,
    ]
}
