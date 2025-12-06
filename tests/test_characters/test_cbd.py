from nucypher_core import Conditions, Context

from nucypher_async.characters import MasterKey
from nucypher_async.characters.cbd import ActiveRitual, Decryptor, Encryptor, Recipient


def test_encrypt_and_decrypt() -> None:
    ritual_id = 42
    shares = 3
    threshold = 2

    dkg_nodes = [Decryptor(MasterKey.random()) for _ in range(shares)]
    ritual = ActiveRitual._test_create(ritual_id, dkg_nodes, threshold)

    # Encryptor creates a message
    message = b"message"
    message_kit = Encryptor(MasterKey.random()).encrypt(
        ritual.dkg_public_key, message, Conditions("{conditions}")
    )

    bob = Recipient(MasterKey.random())
    tdr = bob.make_decryption_request(
        ritual_id=ritual_id,
        message_kit=message_kit,
        context=Context("context"),
    )

    responses = []
    for dkg_node in dkg_nodes[:threshold]:
        etdr, shared_secret = bob.encrypt_decryption_request(
            tdr, ritual.participant(dkg_node.card())
        )

        tdr = dkg_node.decrypt_threshold_decryption_request(etdr)
        decryption_share = dkg_node.make_decryption_share(ritual, tdr)

        response = dkg_node.make_threshold_decryption_response(ritual, decryption_share)
        encrypted_response = dkg_node.encrypt_threshold_decryption_response(
            response, etdr.requester_public_key
        )

        # bob decrypts
        responses.append(
            bob.decrypt_threshold_decryption_response(encrypted_response, shared_secret)
        )

    cleartext = bob.decrypt_with_responses(message_kit, responses)

    assert cleartext == message
