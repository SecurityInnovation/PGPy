PGPy: Pretty Good Privacy for Python
====================================

.. image:: https://badge.fury.io/py/PGPy.svg
    :target: http://badge.fury.io/py/PGPy
    :alt: Latest version

.. image:: https://travis-ci.org/Commod0re/PGPy.svg?branch=master
    :target: https://travis-ci.org/Commod0re/PGPy
    :alt: Travis-CI

Homepage: None yet.

`PGPy` is a Python (2 and 3) library for implementing Pretty Good Privacy into Python programs.

Features
--------

RFC 4880 compliance with the following data:

:Packet Tags:
    :Old format: Done
    :New format: Done
:ASCII-armoring:
    :Decoding: Done
    :Encoding: Done
    :CRC24 computation: Done
:Unversioned Packets:
    :Public-Key Encrypted Session Key Packet:
        :Tag: 1
        :Done: No
    :Symmetric-Key Encrypted Session Key Packet:
        :Tag: 3
        :Done: No
    :One-Pass Signature Packet:
        :Tag: 4
        :Done: No
    :Compressed Data Packet:
        :Tag: 8
        :Done: No
    :Symmetrically Encrypted Data Packet:
        :Tag: 9
        :Done: No
    :Marker Packet:
        :Tag: 10
        :Done: No
    :Literal Data Packet:
        :Tag: 11
        :Done: No
    :Trust Packet:
        :Tag: 12
        :Done: Yes
    :User ID Packet:
        :Tag: 13
        :Done: Yes
    :User Attribute Packet:
        :Tag: 17
        :Done: No
    :Sym. Encrypted and Integrity Protected Data Packet:
        :Tag: 18
        :Done: No
    :Modification Detection Code Packet:
        :Tag: 19
        :Done: No
:Versioned Packets:
    :Signature Packet:
        :Tag: 2
        :v3:
            :Parsing: No
            :Creating: No
        :v4:
            :Parsing: Yes
            :Creating: No
    :Secret-Key Packet:
        :Tag: 5
        :v3:
            :Parsing: No
            :Creating: No
        :v4:
            :Parsing: Yes
            :Creating: No
    :Public-Key Packet:
        :Tag: 6
        :v3:
            :Parsing: No
            :Creating: No
        :v4:
            :Parsing: Yes
            :Creating: No
    :Secret-Subkey Packet:
        :Tag: 7
        :v3:
            :Parsing: No
            :Creating: No
        :v4:
            :Parsing: Yes
            :Creating: No
    :Public-Subkey Packet:
        :Tag: 14
        :v3:
            :Parsing: No
            :Creating: No
        :v4:
            :Parsing: Yes
            :Creating: No
:Actions:
    :Keys:
        :Generate: None
        :Load Keys:
            :ASCII: Yes
            :GPG Keyrings: Yes
            :GPG Agent: No
        :Load Public Keys:
            :RSA: Yes
            :DSA Sign Only: Yes
            :DSA with ElGamal: Yes
        :Load Private Keys:
            :RSA: Yes
            :DSA Sign Only: Yes
            :DSA with ElGamal: Yes
            :Unencrypted: Yes
            :Encrypted:
                :with IDEA: No
                :with CAST5: Yes
                :with Blowfish: No
                :with AES: No
                :with Twofish: No
        :RSA:
            :Load Private Keys:
                :Unencrypted:
        :DSA:
            :Load Public Keys:
                :ASCII: Yes
                :GPG Keyrings: Yes
                :GPG Agent: No
    :Symmetric-Key:
        :IDEA:
            :Encrypt:
                :Key Material: No
                :Messages: No
            :Decrypt:
                :Key Material: No
                :Messages: No
        :TripleDES:
            :Encrypt:
                :Key Material: No
                :Messages: No
            :Decrypt:
                :Key Material: No
                :Messages: No
        :CAST5:
            :Encrypt:
                :Key Material: No
                :Messages: No
            :Decrypt:
                :Key Material: No
                :Messages: Yes
        :Blowfish:
            :Encrypt:
                :Key Material: No
                :Messages: No
            :Decrypt:
                :Key Material: No
                :Messages: No
        :AES:
            :Encrypt:
                :Key Material: No
                :Messages: No
            :Decrypt:
                :Key Material: No
                :Messages: No
        :Twofish:
            :Encrypt:
                :Key Material: No
                :Messages: No
            :Decrypt:
                :Key Material: No
                :Messages: No
    :Public-Key:
        :RSA:
            :Encrypt: No
            :Decrypt: No
            :Sign:
                :Sign: No
                :Verify: Yes
        :DSA:
            :Encrypt: (ElGamal) No
            :Decrypt: (ElGamal) No
            :Sign:
                :Key Material: No
                :Messages: No

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

- `Cryptography <https://pypi.python.org/pypi/cryptography>`

License
-------

MIT licensed. See the bundled `LICENSE`_ file for more details.

