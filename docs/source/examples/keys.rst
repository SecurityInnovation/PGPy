Keys
====

Loading Keys
------------

There are two ways to load keys: individually, or in a keyring.

Loading Keys Individually
^^^^^^^^^^^^^^^^^^^^^^^^^

Keys can be loaded individually into PGPKey objects::

    # A new, empty PGPkey object can be instantiated, but this is not very useful by itself.
    # ASCII or binary data can be parsed into an empty PGPKey object with the .parse() method
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

    # the only advantage to doing it this way, is the .load method returns a set containing the fingerprints
    # of all keys and subkeys that were loaded this time
    kr = pgpy.PGPKeyring()
    loaded = kr.load(glob.glob(os.path.expanduser('~/.gnupg/*ring.gpg')))

Key Operations
--------------

Once you have a key, or multiple keys, loaded, there are some things you may need to do before they can be used.

Unlocking Protected Secret Keys
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you have a key that is protected with a passphrase, you will need to unlock it first. PGPy handles this using
a context manager block, which also removes the unprotected key material from the object once execution exits that block.

Key unlocking is quite simple::

    # enc_key.is_public is False
    # enc_key.is_protected is True
    # enc_key.is_unlocked is False
    # Note that this context manager does not actually yield anything.
    # If the passphrase given is incorrect, this will raise PGPDecryptionError
    with enc_key.unlock("C0rrectPassphr@se"):
        # enc_key.is_unlocked is now True
        ...

Exporting Keys
^^^^^^^^^^^^^^

Keys can be exported in OpenPGP compliant binary or ASCII-armored formats.

In Python 3::

    # binary
    keybytes = bytes(key)

    # ASCII armored
    keystr = str(key)

in Python 2::

    # binary
    keybytes = key.__bytes__()

    # ASCII armored
    keystr = str(key)

