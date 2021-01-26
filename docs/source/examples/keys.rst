Keys
====

Generating Keys
---------------

PGPy can generate most types keys as defined in the standard.

Generating Primary Keys
^^^^^^^^^^^^^^^^^^^^^^^

It is possible to generate most types of keys with PGPy now. The process is mostly straightforward::

    from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

    # we can start by generating a primary key. For this example, we'll use RSA, but it could be DSA or ECDSA as well
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

    # we now have some key material, but our new key doesn't have a user ID yet, and therefore is not yet usable!
    uid = pgpy.PGPUID.new('Abraham Lincoln', comment='Honest Abe', email='abraham.lincoln@whitehouse.gov')

    # now we must add the new user id to the key. We'll need to specify all of our preferences at this point
    # because PGPy doesn't have any built-in key preference defaults at this time
    # this example is similar to GnuPG 2.1.x defaults, with no expiration or preferred keyserver
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
                ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])

Specifying key expiration can be done using the ``key_expiration`` keyword when adding the user id. Expiration can be specified
using a :py:obj:`datetime.datetime` or a :py:obj:`datetime.timedelta` object::

    from datetime import timedelta

    # in this example, we'll use fewer preferences for the sake of brevity, and set the key to expire in 1 year
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new('Nikola Tesla')  # comment and email are optional

    # the key_expires keyword accepts a :py:obj:`datetime.datetime`
    key.add_uid(uid, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA512, HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.Camellia256],
                compression=[CompressionAlgorithm.BZ2, CompressionAlgorithm.Uncompressed],
                key_expiration=timedelta(days=365))

Generating Sub Keys
^^^^^^^^^^^^^^^^^^^

Generating a subkey is similar to the process above, except that it requires an existing primary key::

    # assuming we already have a primary key, we can generate a new key and add it as a subkey thusly:
    subkey = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

    # preferences that are specific to the subkey can be chosen here
    # any preference(s) needed for actions by this subkey that not specified here
    # will seamlessly "inherit" from those specified on the selected User ID
    key.add_subkey(subkey, usage={KeyFlags.Authentication})

Loading Keys
------------

There are two ways to load keys: individually, or in a keyring.

Loading Keys Individually
^^^^^^^^^^^^^^^^^^^^^^^^^

Keys can be loaded individually into PGPKey objects::

    # A new, empty PGPkey object can be instantiated, but this is not very useful
    # by itself.
    # ASCII or binary data can be parsed into an empty PGPKey object with the .parse()
    # method
    empty_key = pgpy.PGPKey()
    empty_key.parse(keyblob)

    # A key can be loaded from a file, like so:
    key, _ = pgpy.PGPKey.from_file('path/to/key.asc')

    # or from a text or binary string/bytes/bytearray that has already been read in:
    key, _ = pgpy.PGPKey.from_blob(keyblob)

Loading Keys Into a Keyring
^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you intend to maintain multiple keys in memory for extended periods, using a PGPKeyring may be more appropriate::

    # These two methods are mostly equivalent
    kr = pgpy.PGPKeyring(glob.glob(os.path.expanduser('~/.gnupg/*ring.gpg')))

    # the only advantage to doing it this way, is the .load method returns a set containing
    #  the fingerprints of all keys and subkeys that were loaded this time
    kr = pgpy.PGPKeyring()
    loaded = kr.load(glob.glob(os.path.expanduser('~/.gnupg/*ring.gpg')))

Key Operations
--------------

Once you have one or more keys generated or loaded, there are some things you may need or want to do before they can be used.

Passphrase Protecting Secret Keys
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is usually recommended to passphrase-protect private keys. Adding a passphrase to a key is simple::

    # key.is_public is False
    # key.is_protected is False
    key.protect("C0rrectPassphr@se", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    # key.is_protected is now True

Unlocking Protected Secret Keys
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you have a key that is protected with a passphrase, you will need to unlock it first. PGPy handles this using
a context manager block, which also removes the unprotected key material from the object once execution exits that block.

Key unlocking is quite simple::

    # enc_key.is_public is False
    # enc_key.is_protected is True
    # enc_key.is_unlocked is False
    # Note that this context manager yields self, so while you can supply `as cvar`, it isn't strictly required
    # If the passphrase given is incorrect, this will raise PGPDecryptionError
    with enc_key.unlock("C0rrectPassphr@se"):
        # enc_key.is_unlocked is now True
        ...

    # This form works equivalently, but may be more semantically clear in some cases:
    with enc_key.unlock("C0rrectPassphr@se") as ukey:
        # ukey is just a reference to enc_key in this case
        ...

Exporting Keys
^^^^^^^^^^^^^^

Keys can be exported in OpenPGP compliant binary or ASCII-armored formats.

In Python 3::

    # binary
    keybytes = bytes(key)

    # ASCII armored private key
    keystr = str(key)
    
    # ASCII armored public key
    keystr = str(key.pubkey)

in Python 2::

    # binary
    keybytes = key.__bytes__()

    # ASCII armored
    keystr = str(key)
