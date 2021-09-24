Actions
=======

Signing Things
--------------

One of the things you may want to do with PGPKeys is to sign things. This is split into several categories in order
to keep the method signatures relatively simple. Remember that signing requires a private key.

Text/Messages/Other
^^^^^^^^^^^^^^^^^^^

Text and messages can be signed using the .sign method::

    # sign some text
    sig = sec.sign("I have just signed this text!")

    # sign a message
    # the bitwise OR operator '|' is used to add a signature to a PGPMessage.
    message |= sec.sign(message)

    # timestamp signatures can also be generated, like so.
    # Note that GnuPG seems to have no idea what to do with this
    timesig = sec.sign(None)

    # if optional parameters are supplied, then a standalone signature is created
    # instead of a timestamp signature. Effectively, they are equivalent, except
    # that the standalone signature has more information in it.
    lone_sig = sec.sign(None, notation={"cheese status": "standing alone"})

Keys/User IDs
^^^^^^^^^^^^^

Keys and User IDs can be signed using the .certify method::

    # Sign a key - this creates a Signature Directly On A Key.
    # GnuPG only partially supports this type of signature.
    someones_pubkey |= mykey.certify(someones_pubkey)

    # Sign the primary User ID - this creates the usual certification signature
    # that is best supported by other popular OpenPGP implementations.
    # As above, the bitwise OR operator '|' is used to add a signature to a PGPUID.
    cert = mykey.certify(someones_pubkey.userids[0], level=SignatureType.Persona_Cert)
    someones_pubkey.userids[0] |= cert

    # If you want to sign all of their User IDs, that can be done easily in a loop.
    # This is equivalent to GnuPG's default behavior when signing someone's public key.
    # As above, the bitwise OR operator '|' is used to add a signature to a PGPKey.
    for uid in someones_pubkey.userids:
        uid |= mykey.certify(uid)

Verifying Things
----------------

Although signing things uses multiple methods, there is only one method to remember for verifying signatures::

    # verify a detached signature
    pub.verify("I have just signed this text!", sig)

    # verify signatures in a message
    pub.verify(message)

    # verify signatures on a userid
    for uid in someones_pubkey.userids:
        pub.verify(uid)

    # or, better yet, verify all applicable signatures on a key in one go
    pub.verify(someones_pubkey)

Encryption
----------

Another thing you may want to do is encrypt or decrypt messages.

Encrypting/Decrypting Messages With a Public Key
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Encryption using keys requires a public key, while decryption requires a private key. PGPy currently only supports
asymmetric encryption/decryption using RSA or ECDH::

    # Assume the sender has retrieved the public key and saved it to a file.
    # reload the public key 
    pubkey, _ = PGPKey.from_file("PATH TO PUBLIC KEY FILE")

    # As usual, construct a PGPMessage from a string:
    message = PGPMessage.new("42 is quite a pleasant number")

    # Transform it into a new PGPMessage that contains an encrypted form of the
    # unencrypted message
    encrypted_message = pubkey.encrypt(message)

    # Recipient loads the private key
    key, _ = PGPKey.from_file("PATH TO _PRIVATE_ KEY FILE")

    # after the sender sends the encrypted message, the recipient decrypts:
    plaintext = key.decrypt(encrypted_message).message

Encrypting Messages to Multiple Recipients
""""""""""""""""""""""""""""""""""""""""""

.. warning::
    Care must be taken when doing this to delete the session key as soon as possible after encrypting the message.

Messages can also be encrypted to multiple recipients by pre-generating the session key::

    # The symmetric cipher should be specified, in case the first preferred cipher is not
    #  the same for all recipients' public keys
    cipher = pgpy.constants.SymmetricKeyAlgorithm.AES256
    sessionkey = cipher.gen_key()

    # encrypt the message to multiple recipients
    # A decryption passphrase can be added at any point as well, as long as cipher
    #  and sessionkey are also provided to enc_msg.encrypt
    enc_msg = pubkey1.encrypt(message, cipher=cipher, sessionkey=sessionkey)
    enc_msg = pubkey2.encrypt(enc_msg, cipher=cipher, sessionkey=sessionkey)

    # do at least this as soon as possible after encrypting to the final recipient
    del sessionkey

Encrypting/Decrypting Messages With a Passphrase
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are some situations where encrypting a message with a passphrase may be more desirable than doing so with
someone else's public key. That can be done like so::

    # the .encrypt method returns a new PGPMessage object which contains the encrypted
    # contents of the old message
    enc_message = message.encrypt("S00per_Sekr3t")

    # message.is_encrypted is False
    # enc_message.is_encrypted is True
    # a message that was encrypted using a passphrase can also be decrypted using
    # that same passphrase
    dec_message = enc_message.decrypt("S00per_Sekr3t")


Ignoring Usage Flags
^^^^^^^^^^^^^^^^^^^^

.. warning:: Don't do this unless you're *really* sure you need to!

Sometimes a key is created without the correct usage flags and an error is raised when you try to use the key::

    >>> from pgpy import PGPKey, PGPMessage
    >>> key, _ = PGPKey.from_file('path/to/key_without_usage_flags.asc')
    >>> message = PGPMessage.new('secret message')
    >>> encrypted_phrase = key.encrypt(message)
    PGPError: Key 0123456789ABCDEF does not have the required usage flag EncryptStorage, EncryptCommunications

To disable this check, set ``_require_usage_flags`` to ``False`` on the key before calling the problem function::

    >>> from pgpy import PGPKey, PGPMessage
    >>> key, _ = PGPKey.from_file('path/to/key_without_usage_flags.asc')
    >>> key._require_usage_flags = False
    >>> message = PGPMessage.new('secret message')
    >>> encrypted_phrase = key.encrypt(message)
