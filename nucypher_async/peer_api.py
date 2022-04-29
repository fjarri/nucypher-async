from abc import ABC, abstractmethod

from .utils.logging import Logger


class PeerRequest(ABC):

    @abstractmethod
    def remote_host(self) -> str:
        ...

    def data(self) -> bytes:
        ...


class PeerAPI(ABC):

    @abstractmethod
    async def start(self, nursery):
        ...

    @abstractmethod
    async def stop(self):
        ...

    @abstractmethod
    async def endpoint_ping(self, req: PeerRequest) -> str:
        ...

    @abstractmethod
    async def endpoint_node_metadata_get(self, req: PeerRequest) -> bytes:
        ...

    @abstractmethod
    async def endpoint_node_metadata_post(self, req: PeerRequest) -> bytes:
        ...

    @abstractmethod
    async def endpoint_public_information(self, req: PeerRequest) -> bytes:
        ...

    @abstractmethod
    async def endpoint_reencrypt(self, req: PeerRequest) -> bytes:
        ...

    # NOTE: This method really does not belong in the PeerAPI, because it is strictly HTTP,
    # while peers can theoretically use gRPC, or Noise, or something else.
    # But the way the protocol works now, it is hardcoded that the status page
    # should be available at the same port as the rest of the API, so it has to stay here.
    @abstractmethod
    async def endpoint_status(self, req: PeerRequest) -> str:
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
