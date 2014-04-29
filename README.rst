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
   - [x] Old format
   - [x] New format
- ASCII-armoring
   - [x] Decoding
   - [x] Encoding
   - [x] CRC24 computation
- Packets without version distinctions
   - [ ] Public-Key Encrypted Session Key Packet (Tag 1)
   - [ ] Symmetric-Key Encrypted Session Key Packet (Tag 3)
   - [ ] One-Pass Signature Packet (Tag 4)
   - [ ] Compressed Data Packet (Tag 8)
   - [ ] Symmetrically Encrypted Data Packet (Tag 9)
   - [ ] Marker Packet (Tag 10)
   - [ ] Literal Data Packet (Tag 11)
   - [x] Trust Packet (Tag 12)
   - [x] User ID Packet (Tag 13)
   - [ ] User Attribute Packet (Tag 17)
   - [ ] Sym. Encrypted and Integrity Protected Data Packet (Tag 18)
   - [ ] Modification Detection Code Packet (Tag 19)
- v3 Packets
   - [ ] Signature Packet (Tag 2)
   - [ ] Secret-Key Packet (Tag 5)
   - [ ] Public-Key Packet (Tag 6)
   - [ ] Secret-Subkey Packet (Tag 7)
   - [ ] Public-Subkey Packet (Tag 14)
- v4 Packets
   - [x] Signature Packet (Tag 2)
   - [x] Secret-Key Packet (Tag 5)
   - [x] Public-Key Packet (Tag 6)
   - [x] Secret-Subkey Packet (Tag 7)
   - [x] Public-Subkey Packet (Tag 14)
- Actions
   - [ ] Generate keys
   - [ ] Load Public Keys
   - [ ] Load Secret Keys
   - [ ] Sign data
   - [ ] Verify data signature
   - [ ] Encrypt data
   - [ ] Decrypt data

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

