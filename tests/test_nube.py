import pytest
import trio

from nucypher_async.server import mock_start_in_nursery
from nucypher_async.mock_nube.nube import *
from nucypher_async.middleware import MockMiddleware
from nucypher_async.ursula import Ursula, UrsulaServer
from nucypher_async.dkg import Enrico, Bob, MockBlockchain, KeyMakerServer
from nucypher_async.learner import Learner


def test_low_level_api():

    threshold = 2
    shares = 3

    # Keymakers
    # ---------

    keymakers = [KeyMaker.random() for _ in range(4)]

    # This is published and is accessible via a side channel
    keymaker_vks = [keymaker.verifying_key() for keymaker in keymakers]

    # Encryptor
    # ---------

    # Gets the key parts
    key_parts = [keymaker.encryption_key() for keymaker in keymakers]

    # Verifies that they come from the known keymakers
    verified_key_parts = [key_part.verify(vk) for key_part, vk in zip(key_parts, keymaker_vks)]

    # Accumulates the encryption key
    encryption_key = verified_key_parts[0] + verified_key_parts[1] + verified_key_parts[2] + verified_key_parts[3]

    # Encrypts the message
    message = "top secret message"
    capsule, ciphertext = encrypt(encryption_key, message)

    # Recipient
    # ---------

    # Creates a secret key for decryption,
    # and a public key that will be a target for keyslivers/keyfrags.
    recipient_sk = RecipientSecretKey.random()
    recipient_pk = recipient_sk.public_key()

    # Author
    # ------

    # Author creates a label and sends it to Keymakers, requesting key slivers
    label = b"some label"

    # Keymakers make key slivers intended for Recipient
    kslivers = [keymaker.make_key_sliver(label, recipient_pk, threshold, shares)
                for keymaker in keymakers]

    # The slivers are sent back to the Author who repackages them into kfrags.
    kfrags = generate_kfrags(kslivers)

    # Proxies
    # -------

    # Proxies reencrypt the keyfrags.
    cfrags = [reencrypt(capsule, kfrag) for kfrag in kfrags]

    # Recipient
    # ---------

    # Recipient verifies that cfrags originate from known keymakers
    verified_cfrags = [cfrag.verify(keymaker_vks) for cfrag in cfrags]

    # Recipient decryptis with 2 out of 3 cfrags
    decrypted_message = decrypt(recipient_sk, [verified_cfrags[0], verified_cfrags[2]], ciphertext)

    assert decrypted_message == message


@pytest.fixture
def ursulas():
    yield [Ursula() for i in range(10)]


@pytest.fixture
def keymakers():
    yield [KeyMaker.random() for i in range(4)]


@pytest.fixture
def mock_middleware():
    yield MockMiddleware()


@pytest.fixture
def mock_blockchain(ursula_servers):
    yield MockBlockchain(ursula_servers)


@pytest.fixture
def ursula_servers(mock_middleware, ursulas):
    servers = []
    for i in range(10):
        server = UrsulaServer(ursulas[i], port=9150 + i, middleware=mock_middleware)
        servers.append(server)
        mock_middleware.add_server(server)

    # pre-learn about other Ursulas
    for i in range(10):
        # TODO: error-prone, make a Learner method
        metadatas = [server.metadata() for server in servers]
        servers[i].learner._verified_nodes = {metadata.node_id: metadata for metadata in metadatas}

    yield servers


async def test_dkg_granting(nursery, autojump_clock, ursula_servers, mock_middleware, mock_blockchain):

    ursula_handles = [mock_start_in_nursery(nursery, server) for server in ursula_servers]

    # Accessed via network, but they don't have to know about each other,
    # So we'll call their methods directly.
    keymaker_servers = [KeyMakerServer() for _ in range(4)]

    # Enrico could ask some centralized server to get him parts of encryption keys...
    # But he'll have to get the verifying keys from them independently anyway.
    enrico = Enrico()

    label = "some label"

    # Here Enrico contacts the keymakers and gets key parts by label
    encrypting_key = enrico.make_encrypting_key(label, keymaker_servers)

    plaintext = "secret message"
    capsule, ciphertext = enrico.encrypt(encrypting_key, plaintext)

    # Bob wants to request access
    bob = Bob()

    policy = bob.purchase(mock_blockchain, label, threshold=2, shares=3)

    learner = Learner(mock_middleware, seed_contacts=[ursula_servers[0].ssl_contact.contact])
    for _ in range(30):
        await learner.learning_round()

    treasure_maps = [
        keymaker_server.get_treasure_map(mock_blockchain, label)
        for keymaker_server in keymaker_servers
        ]

    cfrags = await bob.retrieve_cfrags(learner, capsule, policy, treasure_maps)

    # Recipient verifies that cfrags originate from known keymakers
    keymaker_vks = [keymaker_server.keymaker.verifying_key() for keymaker_server in keymaker_servers]
    verified_cfrags = [cfrag.verify(keymaker_vks) for cfrag in cfrags]

    # Recipient decryptis with 2 out of 3 cfrags
    decrypted = decrypt(bob.secret_key, verified_cfrags, ciphertext)

    assert decrypted == plaintext
