from abc import ABC, abstractmethod
from pathlib import Path

from .p2p.ursula import UrsulaInfo


class BaseStorage(ABC):
    @abstractmethod
    def get_my_ursula_info(self) -> UrsulaInfo | None: ...

    @abstractmethod
    def set_my_ursula_info(self, ursula_info: UrsulaInfo) -> None: ...


class InMemoryStorage(BaseStorage):
    def __init__(self) -> None:
        self._my_ursula_info: UrsulaInfo | None = None

    def get_my_ursula_info(self) -> UrsulaInfo | None:
        return self._my_ursula_info

    def set_my_ursula_info(self, ursula_info: UrsulaInfo) -> None:
        self._my_ursula_info = ursula_info


class FileSystemStorage(BaseStorage):
    def __init__(self, storage_dir: Path):
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)

    def _my_ursula_info_path(self) -> Path:
        return self._storage_dir / "operator.metadata"

    def get_my_ursula_info(self) -> UrsulaInfo | None:
        ursula_info_path = self._my_ursula_info_path()
        if not ursula_info_path.is_file():
            return None

        with ursula_info_path.open("rb") as file:
            ursula_info = file.read()

        return UrsulaInfo.from_bytes(ursula_info)

    def set_my_ursula_info(self, ursula_info: UrsulaInfo) -> None:
        ursula_info_path = self._my_ursula_info_path()
        with ursula_info_path.open("wb") as file:
            file.write(bytes(ursula_info))
