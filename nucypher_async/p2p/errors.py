"""
A peer interface is intentionally distantiated from an HTTP server,
to illustrate that it does not necessarily need to work via HTTP.
"""

import json
from enum import IntEnum, unique
from typing import Any

from ..base.types import JSON


@unique
class PeerErrorCode(IntEnum):
    UNKNOWN = 0
    GENERIC = 1
    INVALID_MESSAGE = 2
    INACTIVE_POLICY = 3


class PeerError(Exception):
    """
    A base class for errors that can be passed through whatever transport
    clients use to connect peers.
    """

    def __init__(self, code: PeerErrorCode, error: str):
        super().__init__(f"PeerError({code}): {error}")
        self.code = code
        self.error = error

    @staticmethod
    def from_bytes(encoded_json: bytes) -> "PeerError":
        try:
            parsed_message = json.loads(encoded_json)
        except json.decoder.JSONDecodeError:
            # Support for other implementation that just returns strings
            return PeerError.unknown(encoded_json.decode())

        if not isinstance(parsed_message, dict):
            return PeerError.unknown(f"Peer error message is not a dictionary: {parsed_message}")

        try:
            code = parsed_message["code"]
        except KeyError:
            return PeerError.unknown(f"'code' is not set in the error dict: {parsed_message}")

        try:
            error = parsed_message["error"]
        except KeyError:
            return PeerError.unknown(f"'error' is not set in the error dict: {parsed_message}")

        try:
            typed_code = PeerErrorCode(code)
        except ValueError:
            return PeerError.unknown(f"Unknown peer error code {code}: {parsed_message}")

        return PeerError(typed_code, error)

    def to_json(self) -> JSON:
        return dict(error=self.error, code=self.code.value)

    @staticmethod
    def unknown(error: str) -> "PeerError":
        return PeerError(PeerErrorCode.UNKNOWN, error)

    @staticmethod
    def generic(error: str) -> "PeerError":
        return PeerError(PeerErrorCode.GENERIC, error)

    @staticmethod
    def invalid_message(message_cls: type[Any], exc: Exception) -> "PeerError":
        return PeerError(
            PeerErrorCode.INVALID_MESSAGE, f"Failed to parse {message_cls.__name__} bytes: {exc}"
        )

    @staticmethod
    def inactive_policy(error: str) -> "PeerError":
        return PeerError(PeerErrorCode.INACTIVE_POLICY, error)
