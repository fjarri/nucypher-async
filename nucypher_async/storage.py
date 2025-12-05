from abc import ABC, abstractmethod
from pathlib import Path

from .p2p.node_info import NodeInfo


# TODO: add the ability to save certificates
# TODO: add `get_child()` so that it could be used hierarchically
class BaseStorage(ABC):
    @abstractmethod
    def get_my_node_info(self) -> NodeInfo | None: ...

    @abstractmethod
    def set_my_node_info(self, node_info: NodeInfo) -> None: ...


class InMemoryStorage(BaseStorage):
    def __init__(self) -> None:
        self._my_node_info: NodeInfo | None = None

    def get_my_node_info(self) -> NodeInfo | None:
        return self._my_node_info

    def set_my_node_info(self, node_info: NodeInfo) -> None:
        self._my_node_info = node_info


class FileSystemStorage(BaseStorage):
    def __init__(self, storage_dir: Path):
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)

    def _my_node_info_path(self) -> Path:
        return self._storage_dir / "operator.metadata"

    def get_my_node_info(self) -> NodeInfo | None:
        node_info_path = self._my_node_info_path()
        if not node_info_path.is_file():
            return None

        with node_info_path.open("rb") as file:
            node_info = file.read()

        return NodeInfo.from_bytes(node_info)

    def set_my_node_info(self, node_info: NodeInfo) -> None:
        node_info_path = self._my_node_info_path()
        with node_info_path.open("wb") as file:
            file.write(bytes(node_info))
