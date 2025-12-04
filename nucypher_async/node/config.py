from collections.abc import Callable
from ipaddress import IPv4Address
from pathlib import Path

from attrs import frozen
from platformdirs import PlatformDirs

from ..base.time import BaseClock
from ..domain import Domain
from ..drivers.cbd import CBDClient
from ..drivers.http_client import HTTPClient
from ..drivers.identity import IdentityClient
from ..drivers.pre import PREClient
from ..drivers.time import SystemClock
from ..node_base import Contact, PeerPrivateKey, PeerPublicKey
from ..p2p import NodeClient
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
class SSLConfig:
    certificate: SSLCertificate
    private_key: SSLPrivateKey
    ca_chain: list[SSLCertificate]

    @classmethod
    def from_config_values(
        cls,
        *,
        ssl_private_key_path: str,
        ssl_certificate_path: str,
        ssl_ca_chain_path: str | None = None,
    ) -> "SSLConfig":
        with Path(ssl_private_key_path).open("rb") as pk_file:
            ssl_private_key = SSLPrivateKey.from_pem_bytes(pk_file.read())

        with Path(ssl_certificate_path).open("rb") as cert_file:
            ssl_certificate = SSLCertificate.from_pem_bytes(cert_file.read())

        if ssl_ca_chain_path is not None:
            with Path(ssl_ca_chain_path).open("rb") as chain_file:
                ssl_ca_chain = SSLCertificate.list_from_pem_bytes(chain_file.read())
        else:
            ssl_ca_chain = []

        # TODO: check that the SSL certificate corresponds to the given private key

        # TODO: check that certificates in the chain are in the correct order?
        # (root certificate last)
        return cls(
            certificate=ssl_certificate,
            private_key=ssl_private_key,
            ca_chain=ssl_ca_chain,
        )


@frozen
class HTTPServerConfig:
    bind_to_address: IPv4Address
    bind_to_port: int
    ssl_config: SSLConfig | None

    @classmethod
    def from_typed_values(
        cls,
        *,
        bind_to_address: str | IPv4Address,
        bind_to_port: int,
        ssl_config: SSLConfig | None = None,
    ) -> "HTTPServerConfig":
        return cls(
            bind_to_address=IPv4Address(bind_to_address),
            bind_to_port=bind_to_port,
            ssl_config=ssl_config,
        )

    @classmethod
    def from_config_values(
        cls,
        *,
        bind_to_address: str = "127.0.0.1",
        bind_to_port: int,
        ssl_private_key_path: str | None,
        ssl_certificate_path: str | None,
        ssl_ca_chain_path: str | None = None,
    ) -> "HTTPServerConfig":
        if ssl_private_key_path is not None and ssl_certificate_path is not None:
            ssl_config = SSLConfig.from_config_values(
                ssl_private_key_path=ssl_private_key_path,
                ssl_certificate_path=ssl_certificate_path,
                ssl_ca_chain_path=ssl_ca_chain_path,
            )
        elif (
            ssl_private_key_path is None
            and ssl_certificate_path is None
            and ssl_ca_chain_path is None
        ):
            ssl_config = None
        else:
            raise ValueError("Both SSL private key and certificate path must be provided")

        return cls.from_typed_values(
            bind_to_address=bind_to_address,
            bind_to_port=bind_to_port,
            ssl_config=ssl_config,
        )


@frozen
class NodeServerConfig:
    http_server_config: HTTPServerConfig
    contact: Contact
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
    def from_typed_values(
        cls,
        *,
        http_server_config: HTTPServerConfig,
        external_host: str | None = None,
        external_port: int | None = None,
        domain: Domain,
        identity_client: IdentityClient,
        pre_client: PREClient,
        cbd_client: CBDClient,
        node_client: NodeClient | None = None,
        logger: Logger,
        storage: BaseStorage | None = None,
        seed_contacts: list[Contact] | None = None,
        clock: BaseClock = SystemClock(),
    ) -> "NodeServerConfig":
        if (
            http_server_config.ssl_config is not None
            and http_server_config.ssl_config.certificate.declared_host != external_host
        ):
            raise ValueError(
                "The declared external host is `{external_host}`, "
                "but the given SSL certificate has `{ssl_config.certificate.declared_host}`"
            )

        external_host = external_host or str(http_server_config.bind_to_address)
        external_port = external_port or http_server_config.bind_to_port
        storage = storage or InMemoryStorage()

        return cls(
            http_server_config=http_server_config,
            contact=Contact(external_host, external_port),
            domain=domain,
            identity_client=identity_client,
            pre_client=pre_client,
            cbd_client=cbd_client,
            node_client=node_client or NodeClient(HTTPClient()),
            logger=logger,
            storage=storage,
            seed_contacts=seed_contacts or [],
            clock=clock,
        )

    @classmethod
    def from_config_values(
        cls,
        *,
        bind_to_address: str | None,
        bind_to_port: int | None,
        external_host: str,
        external_port: int | None,
        ssl_private_key_path: str | None,
        ssl_certificate_path: str | None,
        ssl_ca_chain_path: str | None,
        identity_endpoint: str,
        pre_endpoint: str,
        cbd_endpoint: str,
        domain: str = "mainnet",
        log_to_console: bool = True,
        log_to_file: bool = True,
        persistent_storage: bool = True,
        debug: bool = False,
        profile_name: str = "node",
        identity_client_factory: Callable[
            [str, Domain], IdentityClient
        ] = IdentityClient.from_endpoint,
        pre_client_factory: Callable[[str, Domain], PREClient] = PREClient.from_endpoint,
        cbd_client_factory: Callable[[str, Domain], CBDClient] = CBDClient.from_endpoint,
    ) -> "NodeServerConfig":
        logger = make_logger(
            profile_name,
            "node",
            log_to_console=log_to_console,
            log_to_file=log_to_file,
            debug=debug,
        )
        clock = SystemClock()

        if bind_to_address is None:
            try:
                bind_to_address = str(IPv4Address(external_host))
            except ValueError as exc:
                raise ValueError(
                    "If `bind_to_address` is not given, it is taken "
                    "to be equal to `external_host`, "
                    f"which in this case must be an IPv4 address (got: {external_host})"
                ) from exc

        external_port = external_port or 9151
        bind_to_port = bind_to_port or external_port

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
        node_client = NodeClient(HTTPClient())

        return cls.from_typed_values(
            http_server_config=http_server_config,
            external_host=external_host,
            external_port=external_port,
            domain=domain_,
            identity_client=identity_client,
            pre_client=pre_client,
            cbd_client=cbd_client,
            node_client=node_client,
            logger=logger,
            storage=storage,
            seed_contacts=seed_contacts,
            clock=clock,
        )

    @property
    def peer_key_pair(self) -> tuple[PeerPrivateKey, PeerPublicKey] | None:
        if self.http_server_config.ssl_config is not None:
            ssl_config = self.http_server_config.ssl_config
            private_key = PeerPrivateKey(ssl_config.private_key)
            public_key = PeerPublicKey(ssl_config.certificate, ssl_config.ca_chain)
            return (private_key, public_key)
        return None
