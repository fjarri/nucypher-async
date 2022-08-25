from abc import ABC, abstractmethod

from pathlib import Path

from .drivers.peer import PeerInfo


class BaseStorage(ABC):
    @abstractmethod
    def get_my_peer_info(self) -> PeerInfo:
        ...

    @abstractmethod
    def set_my_peer_info(self, peer_info: PeerInfo):
        ...


class InMemoryStorage(BaseStorage):
    def __init__(self):
        self._my_peer_info = None

    def get_my_peer_info(self):
        return self._my_peer_info

    def set_my_peer_info(self, peer_info):
        self._my_peer_info = peer_info


class FileSystemStorage(BaseStorage):
    def __init__(self, storage_dir: Path):
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)

    def _my_peer_info_path(self):
        return self._storage_dir / "operator.metadata"

    def get_my_peer_info(self):
        peer_info_path = self._my_peer_info_path()
        if not peer_info_path.is_file():
            return None

        with open(peer_info_path, "rb") as f:
            peer_info = f.read()

        return NodeMetadata.from_bytes(peer_info)

    def set_my_peer_info(self, peer_info):
        peer_info_path = self._my_peer_info_path()
        with open(peer_info_path, "wb") as f:
            f.write(bytes(peer_info))
