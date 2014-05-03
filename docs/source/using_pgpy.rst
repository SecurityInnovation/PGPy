Using PGPy
----------

Installation
^^^^^^^^^^^^

PGPy can be obtained from PyPI using pip:

.. code-block:: bash

    $ pip install PGPy


Using PGPy is quite simple. For all examples given below, use the following import statement::

    import pgpy

Loading Keys
^^^^^^^^^^^^

The first thing you will always want to do is load one or more keys. PGPy understands a wide variety of formats.

You can load ASCII armored keys or GPG keyrings directly using a path, URL, file-like object, string, byte string,
or a list of any of those formats::

    asciikey = pgpy.PGPKeyring("path/to/key.asc")
    keyring = pgpy.PGPKeyring("path/to/keyring.gpg")
    pubsec = pgpy.PGPKeyring(["/home/user/.gnupg/pubring.gpg", "/home/user/.gnupg/secring.gpg"])
    ubuntupubkey = pgpy.PGPKeyring("http://us.archive.ubuntu.com/ubuntu/project/ubuntu-archive-keyring.gpg")


and additional keys can be loaded as you go::

    pubsec = pgpy.PGPKeyring(["/home/user/.gnupg/pubring.gpg", "/home/user/.gnupg/secring.gpg"])
    pubsec.load("path/to/another/key")
    pubsec.load(["another/pubring.gpg", "anther/secring.gpg"])


PGPKeyring also accepts URLs, file-like objects, strings, and byte strings.

Using Keys
^^^^^^^^^^

Once you have some keys loaded, you probably want to do something with them.
The basic pattern for using keys is with a context management block. The :py:meth:`PGPKeyring.key` method
provides that context management::

    with pubsec.key("DEADBEEF"):
        # You can sign things by specifying a private key.
        # If the key is protected, you may need to unlock it first, otherwise, :py:meth:`PGPKeyring.sign` will raise an exception
        if pubsec.selected_privkey.encrypted:
            pubsec.unlock("C0rrectPassphr@se")

        # now sign your document. This can be a path, URL, file-like object, string, or bytes.
        sig = pubsec.sign("path/to/document")

        # if you want to write the signature to disk, that's easy too!
        sig.path = "path/to/document.asc"
        sig.write()

        # You can verify the signature using the public key half of the same key:
        if pubsec.verify("path/to/document", str(sig)):
            print("Signature in memory verified!")

        # or use the signature you just wrote to disk
        if pubsec.verify("path/to/document", "path/to/document.asc"):
            print("Signature on disk verified!")

    # When you exit the context-management block, decrypted secret key material is removed from memory,
    # leaving only the encrypted key material.

    # When verifying documents with signatures, you don't need to specify a specific key ahead of time.
    # PGPy will figure out which key signed it using metadata in the signature:
    ubuntupubkeys = pgpy.PGPKeyring("http://us.archive.ubuntu.com/ubuntu/project/ubuntu-archive-keyring.gpg")
    with ubuntupubkeys.key():
        # PGPKeyring.verify returns a SignatureVerification object which can be compared directly as a boolean.
        # It also retains some additional information you can use:
        sigv = pubsec.verify("http://us.archive.ubuntu.com/ubuntu/dists/precise/Release",
                             "http://us.archive.ubuntu.com/ubuntu/dists/precise/Release.gpg")
        if sigv:
            print("Signature was verified using {key}".format(key=sigv.key.keyid))
