Using PGPy
----------

Installation
^^^^^^^^^^^^

PGPy can be obtained from PyPI using pip:

.. code-block:: bash

    $ pip install PGPy


Using PGPy is quite simple. For all examples given below, use the following import statement:

.. code-block:: python

    import pgpy

Loading Keys
^^^^^^^^^^^^

The first thing you will always want to do is load one or more keys. PGPy understands a wide variety of formats.

You can load ASCII armored keys or GPG keyrings directly using a path or list of paths:

.. code-block:: python

    asciikey = pgpy.PGPKeyring("path/to/key.asc")
    keyring = pgpy.PGPKeyring("path/to/keyring.gpg")
    pubsec = pgpy.PGPKeyring(["/home/user/.gnupg/pubring.gpg", "/home/user/.gnupg/secring.gpg"])


and additional keys can be loaded as you go:

.. code-block::python

    pubsec = pgpy.PGPKeyring(["/home/user/.gnupg/pubring.gpg", "/home/user/.gnupg/secring.gpg"])
    pubsec.load("path/to/another/key")
    pubsec.load(["another/pubring.gpg", "anther/secring.gpg"])


PGPKeyring also accepts URLs, file-like objects, strings, and byte strings.

Signing Documents
^^^^^^^^^^^^^^^^^

Once you have some keys loaded, you probably want to do something with them.
Signing documents with a private key you have loaded is quite easy:

.. code-block:: python

    with pubsec.key("DEADBEEF"):
        sig = pubsec.sign("path/to/document")

        # if you want to write the signature to disk, that's easy too!
        sig.path = "path/to/newsig.asc"
        sig.write()


The .key() method accepts the short form keyids of 8 hex digits, full length 16 hex digit ids, or key fingerprints
with or without spaces. It can only select one key at a time. Is your secret key encrypted? You can unlock it using the
correct passphrase like so:

.. code-block:: python

    with pubsec.key("DEADBEEF"):
        # pubsec.selected_privkey.encrypted is True
        pubsec.unlock("C0rrectPassphr@se")
        sig = pubsec.sign("path/to/document")


If you try to use a protected key without unlocking it first, it will raise a PGPError.

Verifying Documents with Signatures
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Verifying signatures is also quite easy:

.. code-block:: python

    with pubsec.key():
        if pubsec.verify("path/to/document", sig):
            print("Signature verified!")

If you are verifying a signature, you don't need to specify the key id for the context manager. If no key is specified,
PGPy will use metadata in the signature to determine which public key to use to verify the signature with.
