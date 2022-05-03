from abc import ABC, abstractmethod
from enum import Enum
import json

from .utils.logging import Logger


class PeerErrorCode(Enum):
    UNKNOWN_ERROR = 0
    GENERIC_ERROR = 1 # TODO: should we have it at all?
    INVALID_MESSAGE = 2
    INACTIVE_POLICY = 3


class PeerError(Exception):

    @staticmethod
    def error_code(self):
        return PeerErrorCode.GENERIC_ERROR

    def to_json(self) -> dict:
        return dict(error=self.args[0], code=self.error_code())

    @classmethod
    def from_json(self, message: str):
        parsed_message = json.loads(message)
        code = message["code"]
        error = message["error"]

        if code == InvalidMessage.error_code():
            return InvalidMessage(error)
        elif code == PaymentRequired.error_code():
            return PaymentRequired(error)
        elif code == PeerError.error_code():
            return PeerError(error)
        else:
            return PeerError(f"Unknown code {code}: {error}")


class InvalidMessage(PeerError):

    @staticmethod
    def error_code(self):
        return PeerErrorCode.INVALID_MESSAGE

    @classmethod
    def for_message(cls, message_cls, exc):
        cls(f"Failed to parse {message_cls.__name__} bytes: {exc}")


class InactivePolicy(PeerError):

    @staticmethod
    def error_code(self):
        return PeerErrorCode.INACTIVE_POLICY


class PeerAPI(ABC):

    @abstractmethod
    async def start(self, nursery):
        ...

    @abstractmethod
    async def stop(self):
        ...

    @abstractmethod
    async def endpoint_ping(self, remote_host: str) -> str:
        ...

    @abstractmethod
    async def endpoint_node_metadata_get(self) -> bytes:
        ...

    @abstractmethod
    async def endpoint_node_metadata_post(self, remote_host: str, request_bytes: bytes) -> bytes:
        ...

    @abstractmethod
    async def endpoint_public_information(self) -> bytes:
        ...

    @abstractmethod
    async def endpoint_reencrypt(self, request_bytes: bytes) -> bytes:
        ...

    # NOTE: This method really does not belong in the PeerAPI, because it is strictly HTTP,
    # while peers can theoretically use gRPC, or Noise, or something else.
    # But the way the protocol works now, it is hardcoded that the status page
    # should be available at the same port as the rest of the API, so it has to stay here.
    @abstractmethod
    async def endpoint_status(self) -> str:
        ...

    # TODO: this is a little backwards; the app encompasses the server state,
    # but the app's logger will be a child of the server's logger.
    # Is there a more logical way to create a logger?
    @abstractmethod
    async def logger(self) -> Logger:
        ...


class PeerServer(ABC):

    @abstractmethod
    def secure_contact(self) -> "SecureContact":
        ...

    @abstractmethod
    def peer_private_key(self) -> "PeerPrivateKey":
        ...

    @abstractmethod
    def peer_api(self) -> "PeerAPI":
        ...


class PeerServerHandle(ABC):

    @abstractmethod
    def shutdown(self):
        ...
