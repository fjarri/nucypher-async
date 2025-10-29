from collections.abc import Callable
from pathlib import Path

from attrs import frozen
from platformdirs import PlatformDirs

from ..base.time import BaseClock
from ..domain import Domain
from ..drivers.identity import IdentityClient
from ..drivers.peer import Contact, PeerClient, PeerPrivateKey, PeerPublicKey
from ..drivers.pre import PREClient
from ..drivers.time import SystemClock
from ..storage import BaseStorage, FileSystemStorage, InMemoryStorage
from ..utils.logging import ConsoleHandler, Handler, Level, Logger, RotatingFileHandler
from ..utils.ssl import SSLCertificate, SSLPrivateKey


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
class PeerServerConfig:
    bind_as: str
    contact: Contact
    ssl_certificate: SSLCertificate | None
    ssl_private_key: SSLPrivateKey | None
    ssl_ca_chain: list[SSLCertificate] | None

    @classmethod
    def from_config_values(
        cls,
        *,
        bind_as: str = "127.0.0.1",
        external_host: str,
        port: int,
        ssl_private_key_path: str | Path | None,
        ssl_certificate_path: str | Path | None,
        ssl_ca_chain_path: str | Path | None = None,
    ) -> "PeerServerConfig":
        ssl_private_key: SSLPrivateKey | None
        if ssl_private_key_path is not None:
            with Path(ssl_private_key_path).open("rb") as pk_file:
                ssl_private_key = SSLPrivateKey.from_pem_bytes(pk_file.read())
        else:
            ssl_private_key = None

        ssl_certificate: SSLCertificate | None
        if ssl_certificate_path is not None:
            with Path(ssl_certificate_path).open("rb") as cert_file:
                ssl_certificate = SSLCertificate.from_pem_bytes(cert_file.read())
            if ssl_certificate.declared_host != external_host:
                raise ValueError(
                    "The declared external host is `{external_host}`, "
                    "but the given SSL certificate has `{ssl_certificate.declared_host}`"
                )
            # TODO: check that the SSL certificate corresponds to the given private key
        else:
            ssl_certificate = None

        ssl_ca_chain: list[SSLCertificate] | None
        if ssl_ca_chain_path is not None:
            with Path(ssl_ca_chain_path).open("rb") as chain_file:
                ssl_ca_chain = SSLCertificate.list_from_pem_bytes(chain_file.read())
                # TODO: check that they are in the correct order? (root certificate last)
        else:
            ssl_ca_chain = None

        contact = Contact(external_host, port)

        return cls(
            bind_as=bind_as,
            contact=contact,
            ssl_private_key=ssl_private_key,
            ssl_certificate=ssl_certificate,
            ssl_ca_chain=ssl_ca_chain,
        )

    @property
    def peer_public_key(self) -> PeerPublicKey | None:
        return PeerPublicKey(self.ssl_certificate) if self.ssl_certificate else None

    @property
    def peer_private_key(self) -> PeerPrivateKey | None:
        return PeerPrivateKey(self.ssl_private_key) if self.ssl_private_key else None


@frozen
class UrsulaServerConfig:
    domain: Domain
    identity_client: IdentityClient
    pre_client: PREClient
    peer_client: PeerClient
    parent_logger: Logger
    storage: BaseStorage
    seed_contacts: list[Contact]
    clock: BaseClock

    @classmethod
    def from_config_values(
        cls,
        *,
        identity_endpoint: str,
        pre_endpoint: str,
        domain: str = "mainnet",
        log_to_console: bool = True,
        log_to_file: bool = True,
        persistent_storage: bool = True,
        debug: bool = False,
        profile_name: str = "ursula",
        identity_client_factory: Callable[
            [str, Domain], IdentityClient
        ] = IdentityClient.from_endpoint,
        pre_client_factory: Callable[[str, Domain], PREClient] = PREClient.from_endpoint,
    ) -> "UrsulaServerConfig":
        domain_ = Domain.from_string(domain)
        identity_client = identity_client_factory(identity_endpoint, domain_)
        pre_client = pre_client_factory(pre_endpoint, domain_)
        logger = make_logger(
            profile_name,
            "ursula",
            log_to_console=log_to_console,
            log_to_file=log_to_file,
            debug=debug,
        )
        storage = make_storage(profile_name, persistent_storage=persistent_storage)
        seed_contacts = seed_contacts_for_domain(domain_)
        peer_client = PeerClient()

        return cls(
            domain=domain_,
            identity_client=identity_client,
            pre_client=pre_client,
            peer_client=peer_client,
            parent_logger=logger,
            storage=storage,
            seed_contacts=seed_contacts,
            clock=SystemClock(),
        )


@frozen
class PorterServerConfig:
    domain: Domain
    identity_client: IdentityClient
    peer_client: PeerClient
    parent_logger: Logger
    storage: BaseStorage
    seed_contacts: list[Contact]
    clock: BaseClock

    @classmethod
    def from_config_values(
        cls,
        *,
        identity_endpoint: str,
        debug: bool = False,
        profile_name: str = "porter",
        domain: str = "mainnet",
        log_to_console: bool = True,
        log_to_file: bool = True,
        persistent_storage: bool = True,
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
            debug=debug,
        )
        storage = make_storage(profile_name, persistent_storage=persistent_storage)
        seed_contacts = seed_contacts_for_domain(domain_)
        peer_client = PeerClient()

        return cls(
            domain=domain_,
            identity_client=identity_client,
            peer_client=peer_client,
            parent_logger=logger,
            storage=storage,
            seed_contacts=seed_contacts,
            clock=SystemClock(),
        )
