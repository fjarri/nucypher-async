from collections.abc import Callable
from pathlib import Path

from attrs import frozen
from platformdirs import PlatformDirs

from ..base.time import BaseClock
from ..blockchain.cbd import CBDClient
from ..blockchain.identity import IdentityClient
from ..blockchain.pre import PREClient
from ..domain import Domain
from ..drivers.http_client import HTTPClient
from ..drivers.time import SystemClock
from ..node.config import HTTPServerConfig
from ..p2p import Contact, NodeClient
from ..storage import BaseStorage, FileSystemStorage, InMemoryStorage
from ..utils.logging import ConsoleHandler, Handler, Level, Logger, RotatingFileHandler


# TODO: handle in a centralized way
def seed_contacts_for_domain(domain: Domain) -> list[Contact]:  # noqa: RET503
    if domain == Domain.MAINNET:
        return [Contact("mainnet.nucypher.network", 9151)]
    if domain == Domain.TAPIR:
        return [Contact("tapir.nucypher.network", 9151)]
    if domain == Domain.LYNX:
        return [Contact("lynx.nucypher.network", 9151)]

    # Unreachable since we handle all the possible enum values above.


@frozen
class Directories:
    log_dir: Path
    data_dir: Path


def app_dirs(profile_name: str) -> Directories:
    dirs = PlatformDirs(appname="nucypher-async")
    log_dir = Path(dirs.user_log_dir).resolve() / profile_name
    data_dir = Path(dirs.user_data_dir).resolve() / profile_name
    return Directories(log_dir=log_dir, data_dir=data_dir)


def make_logger(
    profile_name: str,
    log_name: str,
    *,
    log_to_console: bool = True,
    log_to_file: bool = True,
    debug: bool = True,
) -> Logger:
    dirs = app_dirs(profile_name)
    log_handlers: list[Handler] = []
    if log_to_console:
        log_handlers.append(ConsoleHandler())
    if log_to_file:
        log_handlers.append(RotatingFileHandler(log_file=dirs.log_dir / (log_name + ".log")))
    return Logger(level=Level.DEBUG if debug else Level.INFO, handlers=log_handlers)


def make_storage(profile_name: str, *, persistent_storage: bool = True) -> BaseStorage:
    dirs = app_dirs(profile_name)
    if persistent_storage:
        return FileSystemStorage(dirs.data_dir)
    return InMemoryStorage()


@frozen
class ProxyServerConfig:
    http_server_config: HTTPServerConfig
    domain: Domain
    identity_client: IdentityClient
    pre_client: PREClient
    cbd_client: CBDClient
    node_client: NodeClient
    logger: Logger
    storage: BaseStorage
    seed_contacts: list[Contact]
    clock: BaseClock

    @classmethod
    def from_config_values(
        cls,
        *,
        bind_to_address: str = "127.0.0.1",
        bind_to_port: int,
        ssl_private_key_path: str,
        ssl_certificate_path: str,
        ssl_ca_chain_path: str | None = None,
        identity_endpoint: str,
        pre_endpoint: str,
        cbd_endpoint: str,
        debug: bool = False,
        profile_name: str = "proxy",
        domain: str = "mainnet",
        log_to_console: bool = True,
        log_to_file: bool = True,
        persistent_storage: bool = True,
        identity_client_factory: Callable[
            [str, Domain], IdentityClient
        ] = IdentityClient.from_endpoint,
        pre_client_factory: Callable[[str, Domain], PREClient] = PREClient.from_endpoint,
        cbd_client_factory: Callable[[str, Domain], CBDClient] = CBDClient.from_endpoint,
    ) -> "ProxyServerConfig":
        logger = make_logger(
            profile_name,
            "ptoxy",
            log_to_console=log_to_console,
            log_to_file=log_to_file,
            debug=debug,
        )
        clock = SystemClock()

        http_server_config = HTTPServerConfig.from_config_values(
            bind_to_address=bind_to_address,
            bind_to_port=bind_to_port,
            ssl_private_key_path=ssl_private_key_path,
            ssl_certificate_path=ssl_certificate_path,
            ssl_ca_chain_path=ssl_ca_chain_path,
        )

        domain_ = Domain.from_string(domain)
        identity_client = identity_client_factory(identity_endpoint, domain_)
        pre_client = pre_client_factory(pre_endpoint, domain_)
        cbd_client = cbd_client_factory(cbd_endpoint, domain_)

        storage = make_storage(profile_name, persistent_storage=persistent_storage)
        seed_contacts = seed_contacts_for_domain(domain_)

        return cls(
            http_server_config=http_server_config,
            domain=domain_,
            identity_client=identity_client,
            pre_client=pre_client,
            cbd_client=cbd_client,
            node_client=NodeClient(HTTPClient()),
            logger=logger,
            storage=storage,
            seed_contacts=seed_contacts,
            clock=clock,
        )
