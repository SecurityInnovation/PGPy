PGPy: Pretty Good Privacy for Python
====================================

.. image:: https://badge.fury.io/py/PGPy.svg
    :target: https://badge.fury.io/py/PGPy
    :alt: Latest stable version

.. image:: https://travis-ci.com/SecurityInnovation/PGPy.svg?branch=master
    :target: https://travis-ci.com/SecurityInnovation/PGPy?branch=master
    :alt: Travis-CI

.. image:: https://coveralls.io/repos/github/SecurityInnovation/PGPy/badge.svg?branch=master
    :target: https://coveralls.io/github/SecurityInnovation/PGPy?branch=master
    :alt: Coveralls

.. image:: https://readthedocs.org/projects/pgpy/badge/?version=latest
    :target: https://pgpy.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

`PGPy` is a Python library for implementing Pretty Good Privacy into Python programs, conforming to the OpenPGP specification per RFC 4880.

Disclaimer
----------

`PGPy` is a (hopefully) temporary fork of the `main PGPy project <https://github.com/SecurityInnovation/PGPy>`_ with
two patches installed:

1. the removal of a reference to the `imghdr` library, which was removed from the Python3 standard library in 3.13.
2. the requirements for the cryptography library now specify v38 or higher; see `PR #403 <https://github.com/SecurityInnovation/PGPy/pull/403>`_

Support for EOLed versions of python (<3.9) is also removed, but this is purely a package metadata change.

When and if `issue #462 <https://github.com/SecurityInnovation/PGPy/issues/462>`_ is
resolved and a new release of the upstream project happens, this fork will be taken down. I am not proposing to become
PGPy's new maintainer, and will not be accepting pull requests or bug reports at this time.

Features
--------

Currently, PGPy can load keys and signatures of all kinds in both ASCII armored and binary formats.

It can create and verify RSA, DSA, and ECDSA signatures, at the moment. It can also encrypt and decrypt messages using RSA and ECDH.

Installation
------------

To install PGPy, simply:

.. code-block:: bash

    $ pip install PGPy

Documentation
-------------

`PGPy Documentation <https://pgpy.readthedocs.io/en/latest/>`_ on Read the Docs

Discussion
----------

Please report any bugs found on the `issue tracker <https://github.com/SecurityInnovation/PGPy/issues>`_

You can also join ``#pgpy`` on Freenode to ask questions or get involved

Requirements
------------

- Python >= 3.9

  Tested with: 3.13, 3.12, 3.11, 3.10, 3.9

- `Cryptography <https://pypi.python.org/pypi/cryptography>`_

- `pyasn1 <https://pypi.python.org/pypi/pyasn1/>`_

- `six <https://pypi.python.org/pypi/six>`_

License
-------

BSD 3-Clause licensed. See the bundled `LICENSE <https://github.com/SecurityInnovation/PGPy/blob/master/LICENSE>`_ file for more details.
