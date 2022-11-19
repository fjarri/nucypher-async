from abc import ABC, abstractmethod
from typing import Optional
from pathlib import Path

from .p2p.ursula import UrsulaInfo


class BaseStorage(ABC):
    @abstractmethod
    def get_my_ursula_info(self) -> Optional[UrsulaInfo]:
        ...

    @abstractmethod
    def set_my_ursula_info(self, ursula_info: UrsulaInfo) -> None:
        ...


class InMemoryStorage(BaseStorage):
    def __init__(self) -> None:
        self._my_ursula_info: Optional[UrsulaInfo] = None

    def get_my_ursula_info(self) -> Optional[UrsulaInfo]:
        return self._my_ursula_info

    def set_my_ursula_info(self, ursula_info: UrsulaInfo) -> None:
        self._my_ursula_info = ursula_info


class FileSystemStorage(BaseStorage):
    def __init__(self, storage_dir: Path):
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)

    def _my_ursula_info_path(self) -> Path:
        return self._storage_dir / "operator.metadata"

    def get_my_ursula_info(self) -> Optional[UrsulaInfo]:
        ursula_info_path = self._my_ursula_info_path()
        if not ursula_info_path.is_file():
            return None

        with open(ursula_info_path, "rb") as file:
            ursula_info = file.read()

        return UrsulaInfo.from_bytes(ursula_info)

    def set_my_ursula_info(self, ursula_info: UrsulaInfo) -> None:
        ursula_info_path = self._my_ursula_info_path()
        with open(ursula_info_path, "wb") as file:
            file.write(bytes(ursula_info))
