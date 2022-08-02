import json
import sys

from appdirs import AppDirs
import trio
import click

from .drivers.http_server import HTTPServerHandle
from .drivers.peer import PeerHTTPServer
from .drivers.identity import IdentityAccount
from .config import UrsulaServerConfig, PorterServerConfig
from .master_key import EncryptedMasterKey
from .ursula import Ursula
from .ursula_server import UrsulaServer
from .porter_server import PorterServer


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
        profile_name=config.get('profile_name', 'ursula-' + config['domain']),
        domain=config['domain'],
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

    config = PorterServerConfig.from_config_values(
        profile_name=config.get('profile_name', 'porter-' + config['domain']),
        domain=config['domain'],
        identity_endpoint=config['eth_provider_uri'],
        ssl_certificate_path=config['ssl_certificate'],
        ssl_private_key_path=config['ssl_private_key'],
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
    handle = HTTPServerHandle(PeerHTTPServer(server))
    trio.run(handle)


@main.command()
@click.argument('config_path')
def porter(config_path):
    server = make_porter_server(config_path)
    handle = HTTPServerHandle(server)
    trio.run(handle)
