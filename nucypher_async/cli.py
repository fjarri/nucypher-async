import json
import sys

from eth_account import Account
import trio

from .drivers.eth_account import EthAccount
from .drivers.rest_client import Contact
from .drivers.rest_server import serve_forever
from .drivers.eth_client import EthClient
from .master_key import EncryptedMasterKey
from .ursula import Ursula
from .ursula_server import UrsulaServer
from .utils.logging import Logger, ConsoleHandler, RotatingFileHandler


async def make_server():

    config_path = sys.argv[1]
    nucypher_password = sys.argv[2]
    geth_password = sys.argv[3]

    with open(config_path) as f:
        config = json.load(f)

    signer = config['signer_uri']
    assert signer.startswith('keystore://')
    signer = signer[len('keystore://'):]
    with open(signer) as f:
        keyfile = f.read()

    acc = EthAccount.from_payload(keyfile, geth_password)

    with open(config['keystore_path']) as f:
        keystore = json.load(f)

    encrypted_key = EncryptedMasterKey.from_payload(keystore)
    key = encrypted_key.decrypt(nucypher_password)

    ursula = Ursula(master_key=key, eth_account=acc, domain=config['domain'])

    logger = Logger(handlers=[
        ConsoleHandler(),
        RotatingFileHandler(log_file='nucypher.log')])

    server = await UrsulaServer.async_init(
        ursula=ursula,
        eth_client=EthClient.from_http_endpoint(config['eth_provider_uri']),
        port=config['rest_port'],
        host=config['rest_host'],
        seed_contacts=[Contact('ibex.nucypher.network', 9151)],
        parent_logger=logger)

    return server


def main():
    server = trio.run(make_server)
    serve_forever(server)
