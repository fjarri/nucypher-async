from typing import List, Callable, Union, Sequence
from pathlib import Path

from attrs import frozen
from platformdirs import PlatformDirs

from .base.time import BaseClock
from .utils.ssl import SSLCertificate, SSLPrivateKey
from .drivers.time import SystemClock
from .drivers.identity import IdentityClient
from .drivers.payment import PaymentClient
from .drivers.peer import PeerClient, Contact
from .domain import Domain
from .storage import BaseStorage, InMemoryStorage, FileSystemStorage
from .utils.logging import Logger, Handler, ConsoleHandler, RotatingFileHandler


def seed_contacts_for_domain(domain: Domain) -> List[Contact]:
    if domain == Domain.MAINNET:
        return [
            Contact("closest-seed.nucypher.network", 9151),
            Contact("seeds.nucypher.network", 9151),
            Contact("mainnet.nucypher.network", 9151),
        ]
    elif domain == Domain.IBEX:
        return [Contact("ibex.nucypher.network", 9151)]
    elif domain == Domain.ORYX:
        return [Contact("oryx.nucypher.network", 9151)]
    else:
        return []


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
    profile_name: str, log_name: str, log_to_console: bool = True, log_to_file: bool = True
) -> Logger:
    dirs = app_dirs(profile_name)
    log_handlers: List[Handler] = []
    if log_to_console:
        log_handlers.append(ConsoleHandler())
    if log_to_file:
        log_handlers.append(RotatingFileHandler(log_file=dirs.log_dir / (log_name + ".log")))
    return Logger(handlers=log_handlers)


def make_storage(profile_name: str, persistent_storage: bool = True) -> BaseStorage:
    dirs = app_dirs(profile_name)
    if persistent_storage:
        return FileSystemStorage(dirs.data_dir)
    else:
        return InMemoryStorage()


@frozen
class UrsulaServerConfig:

    domain: Domain
    contact: Contact
    identity_client: IdentityClient
    payment_client: PaymentClient
    peer_client: PeerClient
    parent_logger: Logger
    storage: BaseStorage
    seed_contacts: List[Contact]
    clock: BaseClock

    @classmethod
    def from_config_values(
        cls,
        *,
        identity_endpoint: str,
        payment_endpoint: str,
        host: str,
        port: int = 9151,
        domain: str = "mainnet",
        log_to_console: bool = True,
        log_to_file: bool = True,
        persistent_storage: bool = True,
        profile_name: str = "ursula",
        identity_client_factory: Callable[
            [str, Domain], IdentityClient
        ] = IdentityClient.from_endpoint,
        payment_client_factory: Callable[
            [str, Domain], PaymentClient
        ] = PaymentClient.from_endpoint,
    ) -> "UrsulaServerConfig":

        domain_ = Domain.from_string(domain)
        contact = Contact(host, port)
        identity_client = identity_client_factory(identity_endpoint, domain_)
        payment_client = payment_client_factory(payment_endpoint, domain_)
        logger = make_logger(
            profile_name,
            "ursula",
            log_to_console=log_to_console,
            log_to_file=log_to_file,
        )
        storage = make_storage(profile_name, persistent_storage=persistent_storage)
        seed_contacts = seed_contacts_for_domain(domain_)
        peer_client = PeerClient()

        return cls(
            domain=domain_,
            contact=contact,
            identity_client=identity_client,
            payment_client=payment_client,
            peer_client=peer_client,
            parent_logger=logger,
            storage=storage,
            seed_contacts=seed_contacts,
            clock=SystemClock(),
        )


@frozen
class PorterServerConfig:

    domain: Domain
    host: str
    port: int
    ssl_certificate: SSLCertificate
    ssl_private_key: SSLPrivateKey
    identity_client: IdentityClient
    peer_client: PeerClient
    parent_logger: Logger
    storage: BaseStorage
    seed_contacts: List[Contact]
    clock: BaseClock

    @classmethod
    def from_config_values(
        cls,
        *,
        identity_endpoint: str,
        ssl_certificate_path: Union[str, Path],
        ssl_private_key_path: Union[str, Path],
        profile_name: str = "porter",
        domain: str = "mainnet",
        log_to_console: bool = True,
        log_to_file: bool = True,
        persistent_storage: bool = True,
        host: str = "0.0.0.0",
        port: int = 443,
        identity_client_factory: Callable[
            [str, Domain], IdentityClient
        ] = IdentityClient.from_endpoint,
    ) -> "PorterServerConfig":

        domain_ = Domain.from_string(domain)
        identity_client = identity_client_factory(identity_endpoint, domain_)
        logger = make_logger(
            profile_name,
            "porter",
            log_to_console=log_to_console,
            log_to_file=log_to_file,
        )
        storage = make_storage(profile_name, persistent_storage)
        seed_contacts = seed_contacts_for_domain(domain_)
        peer_client = PeerClient()

        with open(ssl_certificate_path, "rb") as f:
            ssl_certificate = SSLCertificate.from_pem_bytes(f.read())

        with open(ssl_private_key_path, "rb") as f:
            ssl_private_key = SSLPrivateKey.from_pem_bytes(f.read())

        return cls(
            domain=domain_,
            host=host,
            port=port,
            ssl_certificate=ssl_certificate,
            ssl_private_key=ssl_private_key,
            identity_client=identity_client,
            peer_client=peer_client,
            parent_logger=logger,
            storage=storage,
            seed_contacts=seed_contacts,
            clock=SystemClock(),
        )
