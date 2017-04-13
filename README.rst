PGPy: Pretty Good Privacy for Python
====================================

.. image:: https://badge.fury.io/py/PGPy.svg
    :target: http://badge.fury.io/py/PGPy
    :alt: Latest stable version

.. image:: https://travis-ci.org/SecurityInnovation/PGPy.svg?branch=develop
    :target: https://travis-ci.org/SecurityInnovation/PGPy?branch=master
    :alt: Travis-CI

.. image:: https://coveralls.io/repos/github/SecurityInnovation/PGPy/badge.png?branch=develop
    :target: https://coveralls.io/github/SecurityInnovation/PGPy?branch=master
    :alt: Coveralls

Homepage: None yet.

`PGPy` is a Python (2 and 3) library for implementing Pretty Good Privacy into Python programs, conforming to the OpenPGP specification per RFC 4880.

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

`PGPy Documentation <https://pythonhosted.org/PGPy/>`_

Discussion
----------

Please report any bugs found on the `issue tracker <https://github.com/SecurityInnovation/PGPy/issues>`_

You can also join ``#pgpy`` on Freenode to ask questions or get involved

Requirements
------------

- Python 3 >= 3.3; Python 2 >= 2.7

  Tested with: 3.6, 3.5, 3.4, 3.3, 2.7

- `Cryptography <https://pypi.python.org/pypi/cryptography>`_

- `enum34 <https://pypi.python.org/pypi/enum34>`_

- `singledispatch <https://pypi.python.org/pypi/singledispatch>`_

- `pyasn1 <https://pypi.python.org/pypi/pyasn1/>`_

- `six <https://pypi.python.org/pypi/six>`_

License
-------

BSD 3-Clause licensed. See the bundled `LICENSE <https://github.com/SecurityInnovation/PGPy/blob/master/LICENSE>`_ file for more details.

