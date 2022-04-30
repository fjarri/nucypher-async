from typing import List
from pathlib import Path

import attrs
from appdirs import AppDirs

from .drivers.ssl import SSLCertificate, SSLPrivateKey
from .drivers.time import Clock, SystemClock
from .drivers.identity import IdentityClient
from .drivers.payment import PaymentClient
from .drivers.peer import PeerClient, Contact
from .domain import Domain
from .storage import Storage, InMemoryStorage, FileSystemStorage
from .utils.logging import Logger, ConsoleHandler, RotatingFileHandler


@attrs.frozen
class UrsulaServerConfig:

    domain: Domain
    contact: Contact
    identity_client: IdentityClient
    payment_client: PaymentClient
    peer_client: PeerClient
    parent_logger: Logger
    storage: Storage
    seed_contacts: List[Contact]
    clock: Clock

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

        contact = Contact(host, port)

        identity_client = identity_client_factory(identity_endpoint, domain)
        payment_client = payment_client_factory(payment_endpoint, domain)

        dirs = AppDirs(appname='nucypher-async')
        log_dir = Path(dirs.user_log_dir).resolve() / profile_name
        data_dir = Path(dirs.user_data_dir).resolve() / profile_name

        log_handlers = (
            ([ConsoleHandler()] if log_to_console else []) +
            ([RotatingFileHandler(log_file=log_dir / 'nucypher.log')] if log_to_file else []))
        logger = Logger(handlers=log_handlers)

        if persistent_storage:
            storage = FileSystemStorage(data_dir)
        else:
            storage = InMemoryStorage()

        if domain not in Domain:
            raise ValueError(f"Unknown domain: {domain}")

        # TODO: move these constants to domain.py?
        if domain == Domain.MAINNET:
            seed_contacts = [
                Contact('closest-seed.nucypher.network', 9151),
                Contact('seeds.nucypher.network', 9151),
                Contact('mainnet.nucypher.network', 9151)]
        elif domain == Domain.IBEX:
            seed_contacts = [
                Contact('ibex.nucypher.network', 9151)]
        else:
            seed_contacts = []

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
    storage: Storage
    seed_contacts: List[Contact]
    clock: Clock

    @classmethod
    def from_config_values(
            cls,
            *,
            identity_endpoint,
            ssl_certificate_path,
            ssl_private_key_path,
            profile_name="porter",
            domain=Domain.MAINNET,
            log_to_console=True,
            log_to_file=True,
            persistent_storage=True,
            host="0.0.0.0",
            port=443,
            identity_client_factory=IdentityClient.from_endpoint,
            ):

        identity_client = identity_client_factory(identity_endpoint, domain)

        with open(ssl_certificate_path, 'rb') as f:
            ssl_certificate = SSLCertificate.from_pem_bytes(f.read())

        with open(ssl_private_key_path, 'rb') as f:
            ssl_private_key = SSLPrivateKey.from_pem_bytes(f.read())

        dirs = AppDirs(appname='nucypher-async')
        log_dir = Path(dirs.user_log_dir).resolve() / profile_name
        data_dir = Path(dirs.user_data_dir).resolve() / profile_name

        log_handlers = (
            ([ConsoleHandler()] if log_to_console else []) +
            ([RotatingFileHandler(log_file=log_dir / 'porter.log')] if log_to_file else []))
        logger = Logger(handlers=log_handlers)

        if persistent_storage:
            storage = FileSystemStorage(data_dir)
        else:
            storage = InMemoryStorage()

        if domain not in Domain:
            raise ValueError(f"Unknown domain: {domain}")

        # TODO: move these constants to domain.py?
        if domain == Domain.MAINNET:
            seed_contacts = [
                Contact('closest-seed.nucypher.network', 9151),
                Contact('seeds.nucypher.network', 9151),
                Contact('mainnet.nucypher.network', 9151)]
        elif domain == Domain.IBEX:
            seed_contacts = [
                Contact('ibex.nucypher.network', 9151)]
        else:
            seed_contacts = []

        peer_client = PeerClient()

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
