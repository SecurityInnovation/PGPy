PGPy: Pretty Good Privacy for Python
====================================

.. image:: https://badge.fury.io/py/PGPy.png
    :target: http://badge.fury.io/py/PGPy
    :alt: Latest version

.. image:: https://travis-ci.org/Commod0re/PGPy.png?branch=master
    :target: https://travis-ci.org/Commod0re/PGPy
    :alt: Travis-CI

Homepage: None yet.

`PGPy` is a Python (2 and 3) library for implementing Pretty Good Privacy into Python programs.

Features
--------

RFC 4880 compliance with the following data:

- Packet Tags
   - &#x2612; Old format
   - &#x2612; New format
- ASCII-armoring
   - &#x2612; Decoding
   - &#x2612; Encoding
   - &#x2612; CRC24 computation
- Packets without version distinctions
   - &#x2610; Public-Key Encrypted Session Key Packet (Tag 1)
   - &#x2610; Symmetric-Key Encrypted Session Key Packet (Tag 3)
   - &#x2610; One-Pass Signature Packet (Tag 4)
   - &#x2610; Compressed Data Packet (Tag 8)
   - &#x2610; Symmetrically Encrypted Data Packet (Tag 9)
   - &#x2610; Marker Packet (Tag 10)
   - &#x2610; Literal Data Packet (Tag 11)
   - &#x2610; Trust Packet (Tag 12)
   - &#x2612; User ID Packet (Tag 13)
   - &#x2610; User Attribute Packet (Tag 17)
   - &#x2610; Sym. Encrypted and Integrity Protected Data Packet (Tag 18)
   - &#x2610; Modification Detection Code Packet (Tag 19)
- v3 Packets
   - &#x2610; Signature Packet (Tag 2)
   - &#x2610; Secret-Key Packet (Tag 5)
   - &#x2610; Public-Key Packet (Tag 6)
   - &#x2610; Secret-Subkey Packet (Tag 7)
   - &#x2610; Public-Subkey Packet (Tag 14)
- v4 Packets
   - &#x2612; Signature Packet (Tag 2)
   - &#x2612; Secret-Key Packet (Tag 5)
   - &#x2612; Public-Key Packet (Tag 6)
   - &#x2612;Secret-Subkey Packet (Tag 7)
   - &#x2612; Public-Subkey Packet (Tag 14)
- Actions
   - &#x2610; Generate keys
   - &#x2610; Load Public Keys
   - &#x2610; Load Secret Keys
   - &#x2610; Sign data
   - &#x2610; Verify data signature
   - &#x2610; Encrypt data
   - &#x2610; Decrypt data

Installation
------------

To install PGPy, simply:

.. code-block:: bash

    $ pip install PGPy

Examples
--------

None yet!

Documentation
-------------

None yet!

Requirements
------------

- Python >= 2.7

  Tested with: 3.4, 3.3, 3.2, 2.7

- `Requests <https://pypi.python.org/pypi/requests>`

License
-------

MIT licensed. See the bundled `LICENSE`_ file for more details.

