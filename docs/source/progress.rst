OpenPGP Implementation Progress
===============================

OpenPGP RFCs
------------

PGPy is focused on eventually reaching complete OpenPGP implementation, adhering to the base OpenPGP message format specification, and eventually, its extension RFCs.

.. progress:: RFC 4880
    :text: PGPy is currently focused on achieving :rfc:`4880` compliance for OpenPGP, which is the latest complete OpenPGP Message Format specification. It supersedes RFC 1991 and RFC 2440.

    :Versioned Packets:
        - Tag 1 v3,  True,  Public-Key Encrypted Session Key Packets
        - Tag 2 v3,  False, Signature Packet
        - Tag 2 v4,  True,  Signature Packet
        - Tag 3 v4,  False, Symmetric-Key Encrypted Session Key Packet
        - Tag 4 v4,  False, One-Pass Signature Packet
        - Tag 5 v3,  False, Secret-Key Packet
        - Tag 5 v4,  True,  Secret-Key Packet
        - Tag 6 v3,  False, Public-Key Packet
        - Tag 6 v4,  True,  Public-Key Packet
        - Tag 7 v3,  False, Secret-Subkey Packet
        - Tag 7 v4,  True,  Secret-Subkey Packet
        - Tag 14 v3, False, Public-SubKey Packet
        - Tag 14 v4, True,  Public-SubKey Packet
        - Tag 18 v1, False, Symetrically Encrypted and Integrity Protected Data Packet

    :Unversioned Packets:
        - Tag 8,  True,  Compressed Data Packet
        - Tag 9,  False, Symetrically Encrypted Data Packet
        - Tag 10, False, Marker Packet
        - Tag 11, True,  Literal Data Packet
        - Tag 12, False, Trust Packet
        - Tag 13, True,  User ID Packet
        - Tag 17, True,  User Attribute Packet
        - Tag 19, False, Modification Detection Code Packet

    :Key Types:
        - RSA,     True, RSA
        - DSA,     True, DSA
        - ElGamal, True, ElGamal

    :Key Sources:
        - Load,     True,  Load from ASCII-armored files
        - Load,     True,  Load from binary files/streams
        - Load,     True,  Load from GPG keyrings
        - Retrieve, False, Retrieve from HKP key servers

    :Key Actions:
        - Generate,  False, Generate RSA Keys
        - Generate,  False, Generate DSA Keys
        - Generate,  False, Generate ElGamal Keys
        - Unprotect, True,  Unprotect private keys encrypted with IDEA*
        - Unprotect, True,  Unprotect private keys encrypted with Triple-DES
        - Unprotect, True,  Unprotect private keys encrypted with CAST5
        - Unprotect, True,  Unprotect private keys encrypted with Blowfish
        - Unprotect, True,  Unprotect private keys encrypted with AES
        - Unprotect, False, Unprotect private keys encrypted with Twofish
        - Protect,   None,  Protect private keys encrypted with IDEA
        - Protect,   False, Protect private keys encrypted with Triple-DES
        - Protect,   False, Protect private keys encrypted with CAST5
        - Protect,   False, Protect private keys encrypted with Blowfish
        - Protect,   False, Protect private keys encrypted with AES
        - Protect,   False, Protect private keys encrypted with Twofish
        - Sign,      True,  Generate detached signatures of binary documents using RSA
        - Sign,      True,  Generate detached signatures of binary documents using DSA
        - Sign,      False, Sign keys
        - Sign,      False, Sign User ID packets
        - Sign,      False, Sign User Attribute packets
        - Sign,      False, Generate key binding signatures
        - Sign,      False, Generate signatures directly on a key
        - Sign,      False, Generate key/subkey/certification revocation signatures
        - Sign,      False, Generate timestamp signatures
        - Sign,      False, Generate third party confirmation signatures
        - Verify,    True,  Verify detached signatures of binary documents using RSA
        - Verify,    True,  Verify detached signatures of binary documents using DSA
        - Verify,    False, Sign keys
        - Verify,    False, False, Sign User ID packets
        - Verify,    False, False, Sign User Attribute packets
        - Verify,    False, False, Generate key binding signatures
        - Verify,    False, False, Generate signatures directly on a key
        - Verify,    False, False, Generate key/subkey/certification revocation signatures
        - Verify,    False, False, Generate timestamp signatures
        - Verify,    False, False, Generate third party confirmation signatures
        - Encrypt,   False, Encrypt data/messages using RSA
        - Encrypt,   False, Encrypt data/messages using ElGamal
        - Encrypt,   False, Encrypt data/messages using symmetric ciphers
        - Decrypt,   False, Decrypt data/messages using RSA
        - Decrypt,   False, Decrypt data/messages using ElGamal
        - Decrypt,   False, Decrypt data/messages using symmetric ciphers

    :Encodings:
        - ASCII,  True, ASCII armored PGP blocks
        - binary, True, binary PGP packets
        - GPG,    True, GPG keyrings


.. comment::
    RFC 3156 (PGP in MIME security)?

.. progress:: RFC 4398
    :text: :rfc:`4398` covers publishing and retrieving PGP public keys via DNS CERT records.

    :Key Sources:
        - DNS CERT, False, Look up and retrieve keys stored in Content-based DNS CERT records
        - DNS CERT, False, Look up and retrieve keys stored in Purpose-based DNS CERT records

.. progress:: RFC 5581
    :text: :rfc:`5881` extends RFC 4880 to officially add support for the Camellia cipher

    :Key Actions:
        - Unprotect, True,  Camellia*
        - Protect,   False, Camellia*

.. progress:: RFC 6637
    :text: :rfc:`6637` extends OpenPGP to officially add support for elliptic curve cryptography

    :Key Types:
        - ECDH,  False, Elliptic Curve Diffie-Hellman
        - ECDSA, False, Elliptic Curve Digital Signature Algorithm

    :Key Actions:
        - Load,     False, Load from ASCII-armored files
        - Load,     False, Load from GPG keyrings
        - Load,     False, Load from GPG agents
        - Generate, False, ECDH
        - Generate, False, ECDSA

.. progress:: Non-RFC Extensions
    :text: This section covers things that are considered extensions to GPG, but are not codified in the form of an RFC.

    :DNS:
        - DNS PKA, False, Look up and retrieve keys stored in DNS PKA records.

.. note::

    \* Cipher depends on the currently installed OpenSSL being compiled with support for it
