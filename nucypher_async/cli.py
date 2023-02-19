from getpass import getpass
import json

import trio
import click

from .drivers.http_server import HTTPServerHandle
from .drivers.peer import UrsulaHTTPServer
from .drivers.identity import IdentityAccount
from .master_key import MasterKey, EncryptedMasterKey
from .characters.pre import Ursula
from .server import UrsulaServerConfig, PorterServerConfig, UrsulaServer, PorterServer


async def make_ursula_server(
    config_path: str, nucypher_password: str, geth_password: str
) -> UrsulaServer:
    with open(config_path, encoding="utf-8") as file:
        config = json.load(file)

    signer = config["signer_uri"]
    assert signer.startswith("keystore://")
    signer = signer[len("keystore://") :]
    with open(signer, encoding="utf-8") as file:
        keyfile = file.read()

    acc = IdentityAccount.from_payload(keyfile, geth_password)

    with open(config["keystore_path"], encoding="utf-8") as file:
        keystore = json.load(file)

    encrypted_key = EncryptedMasterKey.from_payload(keystore)
    key = encrypted_key.decrypt(nucypher_password)

    local_ursula = Ursula(master_key=key, identity_account=acc)

    config = UrsulaServerConfig.from_config_values(
        profile_name=config.get("profile_name", "ursula-" + config["domain"]),
        domain=config["domain"],
        host=config["rest_host"],
        port=config["rest_port"],
        identity_endpoint=config["eth_provider_uri"],
        payment_endpoint=config["payment_provider"],
        log_to_console=True,
        log_to_file=True,
        persistent_storage=True,
        debug=config.get("debug", False),
    )

    server = await UrsulaServer.async_init(ursula=local_ursula, config=config)

    return server


def make_porter_server(config_path: str) -> PorterServer:
    with open(config_path, encoding="utf-8") as file:
        config = json.load(file)

    config = PorterServerConfig.from_config_values(
        profile_name=config.get("profile_name", "porter-" + config["domain"]),
        domain=config["domain"],
        identity_endpoint=config["eth_provider_uri"],
        ssl_certificate_path=config["ssl_certificate"],
        ssl_private_key_path=config["ssl_private_key"],
        ssl_ca_chain_path=config.get("ssl_ca_chain", None),
        debug=config.get("debug", False),
    )

    return PorterServer(config)


@click.group()
def main() -> None:
    pass


@main.command()
@click.argument("config_path")
@click.argument("nucypher_password")
@click.argument("geth_password")
def ursula(config_path: str, nucypher_password: str, geth_password: str) -> None:
    server = trio.run(make_ursula_server, config_path, nucypher_password, geth_password)
    handle = HTTPServerHandle(UrsulaHTTPServer(server))
    trio.run(handle.startup)


@main.command()
@click.argument("config_path")
def porter(config_path: str) -> None:
    server = make_porter_server(config_path)
    handle = HTTPServerHandle(server)
    trio.run(handle.startup)


@main.command()
@click.argument("output_name")
def keygen(output_name: str) -> None:
    words, mk = MasterKey.random_mnemonic()
    password = getpass("Keysore password: ")
    emk = mk.encrypt(password)

    with open(output_name, "w") as f:
        f.write(json.dumps(emk.to_payload(), indent=4))

    print(f"Keystore saved to {output_name}")
    print(f"Mnemonic: {words}")
