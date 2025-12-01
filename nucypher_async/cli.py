import json
from getpass import getpass
from pathlib import Path

import click
import trio

from .characters.cbd import Decryptor
from .characters.node import Operator
from .characters.pre import Reencryptor
from .drivers.http_server import HTTPServerHandle
from .drivers.identity import IdentityAccount
from .drivers.peer import PeerServerHandle
from .master_key import EncryptedMasterKey, MasterKey
from .node import NodeServer, NodeServerConfig
from .proxy import ProxyServer, ProxyServerConfig


async def make_node_server(
    config_path: str, nucypher_password: str, geth_password: str
) -> NodeServer:
    async with await trio.Path(config_path).open(encoding="utf-8") as file:
        config = json.loads(await file.read())

    # TODO: too low level for this method, extract into a classmethod constructor?
    signer = config["signer_uri"]
    assert signer.startswith("keystore://")
    signer = signer[len("keystore://") :]
    async with await trio.Path(signer).open(encoding="utf-8") as file:
        keyfile = await file.read()

    identity_account = IdentityAccount.from_payload(keyfile, geth_password)

    async with await trio.Path(config["keystore_path"]).open(encoding="utf-8") as file:
        keystore = json.loads(await file.read())

    encrypted_key = EncryptedMasterKey.from_payload(keystore)
    master_key = encrypted_key.decrypt(nucypher_password)

    operator = Operator(master_key, identity_account)
    reencryptor = Reencryptor(master_key)
    decryptor = Decryptor(master_key)

    # TODO: put it in `NodeServerConfig.from_nucypher_config()` or something?
    config = NodeServerConfig.from_config_values(
        external_host=config["rest_host"],
        external_port=config.get("rest_port", None),
        bind_to_address=config.get("bind_to_address", None),
        bind_to_port=config.get("bind_to_port", None),
        ssl_certificate_path=config.get("ssl_certificate", None),
        ssl_private_key_path=config.get("ssl_private_key", None),
        ssl_ca_chain_path=config.get("ssl_ca_chain", None),
        profile_name=config.get("profile_name", "node-" + config["domain"]),
        domain=config["domain"],
        identity_endpoint=config["eth_provider_uri"],
        pre_endpoint=config["pre_provider"],
        cbd_endpoint=config["cbd_provider"],
        log_to_console=True,
        log_to_file=True,
        persistent_storage=True,
        debug=config.get("debug", False),
    )

    return await NodeServer.async_init(
        config=config,
        operator=operator,
        reencryptor=reencryptor,
        decryptor=decryptor,
    )


def make_proxy_server(config_path: str) -> ProxyServer:
    with Path(config_path).open(encoding="utf-8") as file:
        config = json.load(file)

    # TODO: check the format of the config the reference implementation uses
    config = ProxyServerConfig.from_config_values(
        bind_to_address=config["bind_to_address"],
        bind_to_port=config["bind_to_port"],
        ssl_certificate_path=config["ssl_certificate"],
        ssl_private_key_path=config["ssl_private_key"],
        ssl_ca_chain_path=config.get("ssl_ca_chain", None),
        profile_name=config.get("profile_name", "proxy-" + config["domain"]),
        domain=config["domain"],
        identity_endpoint=config["eth_provider_uri"],
        pre_endpoint=config["pre_provider_uri"],
        cbd_endpoint=config["cbd_provider_uri"],
        debug=config.get("debug", False),
    )

    return ProxyServer(config)


@click.group()
def main() -> None:
    pass


@main.command()
@click.argument("config_path")
@click.argument("nucypher_password")
@click.argument("geth_password")
def node(config_path: str, nucypher_password: str, geth_password: str) -> None:
    server = trio.run(make_node_server, config_path, nucypher_password, geth_password)
    handle = PeerServerHandle(server)
    trio.run(handle.startup)


@main.command()
@click.argument("config_path")
def proxy(config_path: str) -> None:
    server = make_proxy_server(config_path)
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
