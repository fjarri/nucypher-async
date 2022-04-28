import json
import sys

from appdirs import AppDirs
import trio
import click

from .drivers.peer import Contact
from .drivers.rest_server import serve_forever
from .drivers.identity import IdentityClient, IdentityAccount
from .drivers.payment import PaymentClient
from .config import UrsulaServerConfig, PorterServerConfig
from .master_key import EncryptedMasterKey
from .storage import FileSystemStorage
from .ursula import Ursula
from .domain import Domain
from .ursula_server import UrsulaServer
from .porter_server import PorterServer
from .utils.logging import Logger, ConsoleHandler, RotatingFileHandler


async def make_ursula_server(config_path, nucypher_password, geth_password):

    with open(config_path) as f:
        config = json.load(f)

    signer = config['signer_uri']
    assert signer.startswith('keystore://')
    signer = signer[len('keystore://'):]
    with open(signer) as f:
        keyfile = f.read()

    acc = IdentityAccount.from_payload(keyfile, geth_password)

    with open(config['keystore_path']) as f:
        keystore = json.load(f)

    encrypted_key = EncryptedMasterKey.from_payload(keystore)
    key = encrypted_key.decrypt(nucypher_password)

    ursula = Ursula(master_key=key, identity_account=acc)

    config = UrsulaServerConfig.from_config_values(
        domain=Domain.from_string(config['domain']),
        host=config['rest_host'],
        port=config['rest_port'],
        identity_endpoint=config['eth_provider_uri'],
        payment_endpoint=config['payment_provider'],
        log_to_console=True,
        log_to_file=True,
        persistent_storage=True,
        )

    server = await UrsulaServer.async_init(ursula=ursula, config=config)

    return server


def make_porter_server(config_path):

    with open(config_path) as f:
        config = json.load(f)

    logger = Logger(handlers=[
        ConsoleHandler(),
        RotatingFileHandler(log_file='porter.log')])

    config = PorterServerConfig.from_config_values(
        domain=Domain.from_string(config['domain']),
        host=config['rest_host'],
        port=config['rest_port'] + 4,
        identity_endpoint=config['eth_provider_uri'],
        log_to_console=True,
        log_to_file=True,
        persistent_storage=True,
        )

    return PorterServer(config)


@click.group()
def main():
    pass


@main.command()
@click.argument('config_path')
@click.argument('nucypher_password')
@click.argument('geth_password')
def ursula(config_path, nucypher_password, geth_password):
    server = trio.run(make_ursula_server, config_path, nucypher_password, geth_password)
    serve_forever(server)


@main.command()
@click.argument('config_path')
def porter(config_path):
    server = make_porter_server(config_path)
    serve_forever(server)
