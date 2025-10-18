import json
from getpass import getpass
from pathlib import Path

import click
import trio

from .characters.pre import Ursula
from .drivers.http_server import HTTPServerHandle
from .drivers.identity import IdentityAccount
from .drivers.peer import UrsulaHTTPServer
from .master_key import EncryptedMasterKey, MasterKey
from .server import PorterServer, PorterServerConfig, UrsulaServer, UrsulaServerConfig


async def make_ursula_server(
    config_path: str, nucypher_password: str, geth_password: str
) -> UrsulaServer:
    async with await trio.Path(config_path).open(encoding="utf-8") as file:
        config = json.loads(await file.read())

    signer = config["signer_uri"]
    assert signer.startswith("keystore://")
    signer = signer[len("keystore://") :]
    async with await trio.Path(signer).open(encoding="utf-8") as file:
        keyfile = await file.read()

    acc = IdentityAccount.from_payload(keyfile, geth_password)

    async with await trio.Path(config["keystore_path"]).open(encoding="utf-8") as file:
        keystore = json.loads(await file.read())

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

    return await UrsulaServer.async_init(ursula=local_ursula, config=config)


def make_porter_server(config_path: str) -> PorterServer:
    with Path(config_path).open(encoding="utf-8") as file:
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

    with Path(output_name).open("w") as f:
        f.write(json.dumps(emk.to_payload(), indent=4))

    print(f"Keystore saved to {output_name}")  # noqa: T201
    print(f"Mnemonic: {words}")  # noqa: T201
