from nucypher_async.mock_nube.nube import *


def test_api():

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
