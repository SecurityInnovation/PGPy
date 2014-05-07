PGPy: Pretty Good Privacy for Python
====================================

.. image:: https://badge.fury.io/py/PGPy.svg
    :target: http://badge.fury.io/py/PGPy
    :alt: Latest version

.. image:: https://travis-ci.org/Commod0re/PGPy.svg?branch=master
    :target: https://travis-ci.org/Commod0re/PGPy?branch=master
    :alt: Travis-CI

.. image:: https://coveralls.io/repos/Commod0re/PGPy/badge.png?branch=master
    :target: https://coveralls.io/r/Commod0re/PGPy?branch=master
    :alt: Coveralls

Homepage: None yet.

`PGPy` is a Python (2 and 3) library for implementing Pretty Good Privacy into Python programs.

Features
--------

Currently, PGPy can load keys and signatures of all kinds in both ASCII armored and binary formats.

It can sign and verify RSA signatures only, at the moment.

Installation
------------

To install PGPy, simply:

.. code-block:: bash

    $ pip install PGPy

Examples
--------

.. code-block:: python

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

Documentation
-------------

`PGPy Documentation <http://commod0re.github.io/PGPy/>`

Requirements
------------

- Python >= 2.7

  Tested with: 3.4, 3.3, 3.2, 2.7

- `Requests <https://pypi.python.org/pypi/requests>`_

- `Cryptography <https://pypi.python.org/pypi/cryptography>`_

- `enum34 <https://pypi.python.org/pypi/enum34>`_

License
-------

BSD 3-Clause licensed. See the bundled `LICENSE <https://github.com/Commod0re/PGPy/blob/master/LICENSE>`_ file for more details.

