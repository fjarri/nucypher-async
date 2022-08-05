from typing import List
from pathlib import Path

import attrs
from appdirs import AppDirs

from .base.time import BaseClock
from .utils.ssl import SSLCertificate, SSLPrivateKey
from .drivers.time import SystemClock
from .drivers.identity import IdentityClient
from .drivers.payment import PaymentClient
from .drivers.peer import PeerClient, Contact
from .domain import Domain
from .storage import BaseStorage, InMemoryStorage, FileSystemStorage
from .utils.logging import Logger, ConsoleHandler, RotatingFileHandler


def seed_contacts_for_domain(domain):
    if domain == Domain.MAINNET:
        return [
            Contact('closest-seed.nucypher.network', 9151),
            Contact('seeds.nucypher.network', 9151),
            Contact('mainnet.nucypher.network', 9151)]
    elif domain == Domain.IBEX:
        return [Contact('ibex.nucypher.network', 9151)]
    elif domain == Domain.ORYX:
        return [Contact('oryx.nucypher.network', 9151)]
    else:
        return []


@attrs.frozen
class Directories:
    log_dir: Path
    data_dir: Path


def app_dirs(profile_name):
    dirs = AppDirs(appname='nucypher-async')
    log_dir = Path(dirs.user_log_dir).resolve() / profile_name
    data_dir = Path(dirs.user_data_dir).resolve() / profile_name
    return Directories(log_dir=log_dir, data_dir=data_dir)


def make_logger(profile_name, log_name, log_to_console=True, log_to_file=True):
    dirs = app_dirs(profile_name)
    log_handlers = (
        ([ConsoleHandler()] if log_to_console else []) +
        ([RotatingFileHandler(log_file=dirs.log_dir / (log_name + '.log'))] if log_to_file else []))
    return Logger(handlers=log_handlers)


def make_storage(profile_name, persistent_storage=True):
    dirs = app_dirs(profile_name)
    if persistent_storage:
        return FileSystemStorage(dirs.data_dir)
    else:
        return InMemoryStorage()


@attrs.frozen
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
            identity_endpoint,
            payment_endpoint,
            host,
            port=9151,
            domain=Domain.MAINNET,
            log_to_console=True,
            log_to_file=True,
            persistent_storage=True,
            profile_name="ursula",
            identity_client_factory=IdentityClient.from_endpoint,
            payment_client_factory=PaymentClient.from_endpoint,
            ):

        domain = Domain.from_string(domain)
        contact = Contact(host, port)
        identity_client = identity_client_factory(identity_endpoint, domain)
        payment_client = payment_client_factory(payment_endpoint, domain)
        logger = make_logger(profile_name, 'ursula', log_to_console=log_to_console, log_to_file=log_to_file)
        storage = make_storage(profile_name, persistent_storage=persistent_storage)
        seed_contacts = seed_contacts_for_domain(domain)
        peer_client = PeerClient()

        return cls(
            domain=domain,
            contact=contact,
            identity_client=identity_client,
            payment_client=payment_client,
            peer_client=peer_client,
            parent_logger=logger,
            storage=storage,
            seed_contacts=seed_contacts,
            clock=SystemClock()
            )


@attrs.frozen
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
            identity_endpoint,
            ssl_certificate_path,
            ssl_private_key_path,
            profile_name="porter",
            domain="mainnet",
            log_to_console=True,
            log_to_file=True,
            persistent_storage=True,
            host="0.0.0.0",
            port=443,
            identity_client_factory=IdentityClient.from_endpoint,
            ):

        domain = Domain.from_string(domain)
        identity_client = identity_client_factory(identity_endpoint, domain)
        logger = make_logger(profile_name, 'porter', log_to_console=log_to_console, log_to_file=log_to_file)
        storage = make_storage(profile_name, persistent_storage)
        seed_contacts = seed_contacts_for_domain(domain)
        peer_client = PeerClient()

        with open(ssl_certificate_path, 'rb') as f:
            ssl_certificate = SSLCertificate.from_pem_bytes(f.read())

        with open(ssl_private_key_path, 'rb') as f:
            ssl_private_key = SSLPrivateKey.from_pem_bytes(f.read())

        return cls(
            domain=domain,
            host=host,
            port=port,
            ssl_certificate=ssl_certificate,
            ssl_private_key=ssl_private_key,
            identity_client=identity_client,
            peer_client=peer_client,
            parent_logger=logger,
            storage=storage,
            seed_contacts=seed_contacts,
            clock=SystemClock()
            )
