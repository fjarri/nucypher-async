from abc import ABC, abstractmethod
from typing import Optional
from pathlib import Path

from nucypher_core import NodeMetadata

from .drivers.peer import PeerInfo


class BaseStorage(ABC):
    @abstractmethod
    def get_my_peer_info(self) -> Optional[PeerInfo]:
        ...

    @abstractmethod
    def set_my_peer_info(self, peer_info: PeerInfo) -> None:
        ...


class InMemoryStorage(BaseStorage):
    def __init__(self) -> None:
        self._my_peer_info: Optional[PeerInfo] = None

    def get_my_peer_info(self) -> Optional[PeerInfo]:
        return self._my_peer_info

    def set_my_peer_info(self, peer_info: PeerInfo) -> None:
        self._my_peer_info = peer_info


class FileSystemStorage(BaseStorage):
    def __init__(self, storage_dir: Path):
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)

    def _my_peer_info_path(self) -> Path:
        return self._storage_dir / "operator.metadata"

    def get_my_peer_info(self) -> Optional[PeerInfo]:
        peer_info_path = self._my_peer_info_path()
        if not peer_info_path.is_file():
            return None

        with open(peer_info_path, "rb") as f:
            peer_info = f.read()

        return PeerInfo(NodeMetadata.from_bytes(peer_info))

    def set_my_peer_info(self, peer_info: PeerInfo) -> None:
        peer_info_path = self._my_peer_info_path()
        with open(peer_info_path, "wb") as f:
            f.write(bytes(peer_info))
