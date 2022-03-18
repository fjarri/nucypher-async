import json
import sys

from appdirs import AppDirs
import trio

from .drivers.rest_client import Contact
from .drivers.rest_server import serve_forever
from .drivers.identity import IdentityClient, IdentityAccount
from .drivers.payment import PaymentClient
from .master_key import EncryptedMasterKey
from .storage import FileSystemStorage
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

    acc = IdentityAccount.from_payload(keyfile, geth_password)

    with open(config['keystore_path']) as f:
        keystore = json.load(f)

    encrypted_key = EncryptedMasterKey.from_payload(keystore)
    key = encrypted_key.decrypt(nucypher_password)

    ursula = Ursula(master_key=key, identity_account=acc, domain=config['domain'])

    logger = Logger(handlers=[
        ConsoleHandler(),
        RotatingFileHandler(log_file='nucypher.log')])

    dirs = AppDirs(appname='nucypher-async')
    storage = FileSystemStorage(dirs.user_data_dir)

    server = await UrsulaServer.async_init(
        ursula=ursula,
        identity_client=IdentityClient.from_http_endpoint(config['eth_provider_uri']),
        payment_client=PaymentClient.from_http_endpoint(config['payment_provider']),
        port=config['rest_port'],
        host=config['rest_host'],
        seed_contacts=[Contact('ibex.nucypher.network', 9151)],
        parent_logger=logger,
        storage=storage)

    return server


def main():
    server = trio.run(make_server)
    serve_forever(server)
