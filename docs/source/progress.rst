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
        - Tag 4 v3,  True,  One-Pass Signature Packet
        - Tag 5 v3,  False, Secret-Key Packet
        - Tag 5 v4,  True,  Secret-Key Packet
        - Tag 6 v3,  False, Public-Key Packet
        - Tag 6 v4,  True,  Public-Key Packet
        - Tag 7 v3,  False, Secret-Subkey Packet
        - Tag 7 v4,  True,  Secret-Subkey Packet
        - Tag 14 v3, False, Public-SubKey Packet
        - Tag 14 v4, True,  Public-SubKey Packet
        - Tag 18 v1, True,  Symetrically Encrypted and Integrity Protected Data Packet

    :Unversioned Packets:
        - Tag 8,  True,  Compressed Data Packet
        - Tag 9,  True,  Symetrically Encrypted Data Packet
        - Tag 10, False, Marker Packet
        - Tag 11, True,  Literal Data Packet
        - Tag 12, True,  Trust Packet
        - Tag 13, True,  User ID Packet
        - Tag 17, True,  User Attribute Packet
        - Tag 19, True,  Modification Detection Code Packet

    :Key Types:
        - RSA,     True, RSA
        - DSA,     True, DSA
        - ElGamal, True, ElGamal

    :Key Sources:
        - Load,     True,  Load from ASCII-armored files
        - Load,     True,  Load from binary files/streams
        - Load,     True,  Load from GPG keyrings
        - Retrieve, False, Retrieve from HKP key servers
        - Upload,   False, Submit to HKP key servers

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
        - Sign,      True,  Generate inline signatures of canonical documents using RSA
        - Sign,      True,  Generate inline signatures of canonical documents using DSA
        - Sign,      False, One-Pass Sign messages using RSA
        - Sign,      False, One-Pass Sign messages using DSA
        - Sign,      False, Sign messages using RSA
        - Sign,      False, Sign messages using DSA
        - Sign,      False, Sign keys using RSA
        - Sign,      False, Sign keys using DSA
        - Sign,      False, Certify User IDs using RSA
        - Sign,      False, Certify User IDs using DSA
        - Sign,      False, Sign User Attribute packets using RSA
        - Sign,      False, Sign User Attribute packets using DSA
        - Sign,      False, Generate key binding signatures using RSA
        - Sign,      False, Generate key binding signatures using DSA
        - Sign,      False, Generate signatures directly on a key using RSA
        - Sign,      False, Generate signatures directly on a key using DSA
        - Sign,      False, Generate key/subkey/certification revocation signatures RSA
        - Sign,      False, Generate key/subkey/certification revocation signatures DSA
        - Sign,      False, Generate timestamp signatures using RSA
        - Sign,      False, Generate timestamp signatures using DSA
        - Sign,      False, Generate third party confirmation signatures using RSA
        - Sign,      False, Generate third party confirmation signatures using DSA
        - Verify,    True,  Verify detached signatures of binary documents using RSA
        - Verify,    True,  Verify detached signatures of binary documents using DSA
        - Verify,    True,  Verify inline signatures of canonical documents using RSA
        - Verify,    True,  Verify inline signatures of canonical documents using DSA
        - Verify,    False, Verify key signatures using RSA
        - Verify,    False, Verify key signatures using DSA
        - Verify,    False, Verify User ID certification signatures using RSA
        - Verify,    False, Verify User ID certification signatures using DSA
        - Verify,    False, Verify User Attribute certification signatures using RSA
        - Verify,    False, Verify User Attribute certification signatures using DSA
        - Verify,    False, Verify key binding signatures using RSA
        - Verify,    False, Verify key binding signatures using DSA
        - Verify,    False, Verify signatures directly on a key using RSA
        - Verify,    False, Verify signatures directly on a key using DSA
        - Verify,    False, Verify key/subkey/certification revocation signatures RSA
        - Verify,    False, Verify key/subkey/certification revocation signatures DSA
        - Verify,    False, Verify timestamp signatures using RSA
        - Verify,    False, Verify timestamp signatures using DSA
        - Verify,    False, Verify third party confirmation signatures using RSA
        - Verify,    False, Verify third party confirmation signatures using DSA
        - Encrypt,   False, Encrypt data/messages using RSA
        - Encrypt,   False, Encrypt data/messages using ElGamal
        - Decrypt,   True,  Decrypt data/messages using RSA
        - Decrypt,   False, Decrypt data/messages using ElGamal

    :Other Actions:
        - Encrypt,   True,  Encrypt data/messages using symmetric ciphers with passphrases
        - Decrypt,   True,  Decrypt data/messages using symmetric ciphers with passphrases

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
