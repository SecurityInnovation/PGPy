PGPy: Pretty Good Privacy for Python
====================================

.. image:: https://badge.fury.io/py/PGPy.svg
    :target: http://badge.fury.io/py/PGPy
    :alt: Latest stable version

.. image:: https://travis-ci.org/Commod0re/PGPy.svg?branch=master
    :target: https://travis-ci.org/Commod0re/PGPy?branch=master
    :alt: Travis-CI

.. image:: https://coveralls.io/repos/Commod0re/PGPy/badge.png?branch=master
    :target: https://coveralls.io/r/Commod0re/PGPy?branch=master
    :alt: Coveralls

Homepage: None yet.

`PGPy` is a Python (2 and 3) library for implementing Pretty Good Privacy into Python programs, conforming to the OpenPGP specification per RFC 4880.

Features
--------

Currently, PGPy can load keys and signatures of all kinds in both ASCII armored and binary formats.

It can create and verify RSA and DSA signatures, at the moment.

Installation
------------

To install PGPy, simply:

.. code-block:: bash

    $ pip install PGPy

Documentation
-------------

`PGPy Documentation <https://pythonhosted.org/PGPy/>`_

Requirements
------------

- Python >= 2.7

  Tested with: 3.4, 3.3, 3.2, 2.7

- `Cryptography <https://pypi.python.org/pypi/cryptography>`_

- `enum34 <https://pypi.python.org/pypi/enum34>`_

- `singledispatch <https://pypi.python.org/pypi/singledispatch>`_

- `six <https://pypi.python.org/pypi/six>`_

License
-------

BSD 3-Clause licensed. See the bundled `LICENSE <https://github.com/Commod0re/PGPy/blob/master/LICENSE>`_ file for more details.

