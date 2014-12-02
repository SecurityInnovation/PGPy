*******************************
OpenPGP Implementation Progress
*******************************

OpenPGP RFCs
============

PGPy is focused on eventually reaching complete OpenPGP implementation, adhering to the base OpenPGP message format specification, and its extension RFCs.

.. progress:: RFC 4880
    :text: PGPy is currently focused on achieving :rfc:`4880` compliance for OpenPGP, which is the latest complete OpenPGP Message Format specification. It supersedes RFC 1991 and RFC 2440.

    :Versioned Packets, v1:
        - Tag 18, True,  Symetrically Encrypted and Integrity Protected Data Packet

    :Versioned Packets, v3:
        - Tag 1,  True,  Public-Key Encrypted Session Key Packets
        - Tag 2,  False, Signature Packet
        - Tag 4,  True,  One-Pass Signature Packet
        - Tag 5,  False, Secret-Key Packet
        - Tag 6,  False, Public-Key Packet
        - Tag 7,  False, Secret-Subkey Packet
        - Tag 14, False, Public-SubKey Packet

    :Versioned Packets, v4:
        - Tag 2,  True,  Signature Packet
        - Tag 3,  True,  Symmetric-Key Encrypted Session Key Packet
        - Tag 5,  True,  Secret-Key Packet
        - Tag 6,  True,  Public-Key Packet
        - Tag 7,  True,  Secret-Subkey Packet
        - Tag 14, True,  Public-SubKey Packet

    :Unversioned Packets:
        - Tag 8,  True,  Compressed Data Packet
        - Tag 9,  True,  Symetrically Encrypted Data Packet
        - Tag 10, False, Marker Packet
        - Tag 11, True,  Literal Data Packet
        - Tag 12, True,  Trust Packet
        - Tag 13, True,  User ID Packet
        - Tag 17, True,  User Attribute Packet
        - Tag 19, True,  Modification Detection Code Packet

    :Signature Subpackets:
        - 0x02,  True,  Signature Creation Time
        - 0x03,  True,  Signature Expiration Time
        - 0x04,  True,  Exportable Certification
        - 0x05,  True,  Trust Signature
        - 0x06,  True,  Regular Expression
        - 0x07,  True,  Revocable
        - 0x09,  True,  Key Expiration Time
        - 0x0B,  True,  Preferred Symmetric Algorithms
        - 0x0C,  True,  Revocation Key
        - 0x10,  True,  Issuer
        - 0x14,  True,  Notation Data
        - 0x15,  True,  Preferred Hash Algorithms
        - 0x16,  True,  Preferred Compression Algorithms
        - 0x17,  True,  Key Server Preferences
        - 0x18,  True,  Preferred Key Server
        - 0x19,  True,  Primary User ID
        - 0x1A,  True,  Policy URI
        - 0x1B,  True,  Key Flags
        - 0x1C,  True,  Signer's User ID
        - 0x1D,  True,  Reason For Revocation
        - 0x1E,  True,  Features
        - 0x1F,  False, Siganture Target
        - 0x20,  True,  Embedded Signature

    :User Attribute Subpackets:
        - 0x01, True, Image

    :Storage Formats:
        - ASCII,  True, ASCII armored PGP blocks
        - binary, True, binary PGP packets
        - GPG,    True, GPG keyrings

    :Other Sources:
        - Retrieve, False, Retrieve from HKP key servers
        - Upload,   False, Submit to HKP key servers

    :Key Types:
        - RSA,     True, RSA
        - DSA,     True, DSA
        - ElGamal, True, ElGamal

    :Key Actions:
        - Unprotect, True,  Unprotect private keys encrypted with IDEA*
        - Unprotect, True,  Unprotect private keys encrypted with Triple-DES
        - Unprotect, True,  Unprotect private keys encrypted with CAST5
        - Unprotect, True,  Unprotect private keys encrypted with Blowfish
        - Unprotect, True,  Unprotect private keys encrypted with AES
        - Unprotect, False, Unprotect private keys encrypted with Twofish

    :RSA Key Actions:
        - Load,       True,  Load Keys
        - Generate,   False, Generate Keys
        - Generate,   False, Generate Subkeys
        - Sign,       True,  Generate detached signatures of binary documents
        - Sign,       True,  Generate inline signatures of canonical documents
        - Sign,       True,  Sign messages
        - Sign,       True,  Sign keys
        - Sign,       True,  Certify User IDs
        - Sign,       True,  Certify User Attributes
        - Sign,       True,  Generate key binding signatures
        - Sign,       True,  Revoke certifications
        - Sign,       True,  Revoke keys
        - Sign,       True,  Revoke subkeys
        - Sign,       True,  Generate timestamp signatures
        - Sign,       True,  Generate standalone signatures
        - Sign,       False, Generate third party confirmation signatures
        - Verify,     True,  Verify detached signatures
        - Verify,     True,  Verify inline signatures of canonical documents
        - Verify,     True,  Verify messages
        - Verify,     True,  Verify key signatures
        - Verify,     True,  Verify User ID certification signatures
        - Verify,     True,  Verify User Attribute certification signatures
        - Verify,     True,  Verify key binding signatures
        - Verify,     True,  Verify key revocation signatures
        - Verify,     True,  Verify subkey revocation signatures
        - Verify,     True,  Verify certification revocation signatures
        - Verify,     True,  Verify timestamp signatures
        - Verify,     True,  Verify standalone signatures
        - Verify,     False, Verify third party confirmation signatures
        - Revocation, True,  Designate Revocation Key
        - Revocation, True,  Revoke (Sub)Key with Self Signature
        - Revocation, False, Revoke (Sub)Key using Designated Revocation Key
        - Encryption, True,  Encrypt data/messages
        - Decryption, True,  Decrypt data/messages

    :DSA Key Actions:
        - Load,       True,  Load Keys
        - Generate,   False, Generate Keys
        - Generate,   False, Generate Subkeys
        - Sign,       True,  Generate detached signatures of binary documents
        - Sign,       True,  Generate inline signatures of canonical documents
        - Sign,       True,  One-Pass Sign messages
        - Sign,       True,  Sign messages
        - Sign,       True,  Sign keys
        - Sign,       True,  Certify User IDs
        - Sign,       True,  Certify User Attributes
        - Sign,       True,  Generate key binding signatures
        - Sign,       True,  Revoke certifications
        - Sign,       True,  Revoke keys
        - Sign,       True,  Revoke subkeys
        - Sign,       True,  Generate timestamp signatures
        - Sign,       True,  Generate standalone signatures
        - Sign,       False, Generate third party confirmation signatures
        - Verify,     True,  Verify detached signatures
        - Verify,     True,  Verify inline signatures of canonical documents
        - Verify,     True,  Verify messages
        - Verify,     True,  Verify key signatures
        - Verify,     True,  Verify User ID certification signatures
        - Verify,     True,  Verify User Attribute certification signatures
        - Verify,     True,  Verify key binding signatures
        - Verify,     True,  Verify key revocation signatures
        - Verify,     True,  Verify subkey revocation signatures
        - Verify,     True,  Verify certification revocation signatures
        - Verify,     True,  Verify timestamp signatures
        - Verify,     True,  Verify standalone signatures
        - Verify,     False, Verify third party confirmation signatures
        - Revocation, True,  Designate Revocation Key
        - Revocation, True,  Revoke (Sub)Key with Self Signature
        - Revocation, False, Revoke (Sub)Key using Designated Revocation Key

    :ElGamal Key Actions:
        - Load,       True,  Load Keys
        - Generate,   False, Generate Keys
        - Generate,   False, Generate Subkeys
        - Encryption, False, Encrypt data/messages
        - Decryption, False, Decrypt data/messages

    :Other Actions:
        - Encryption, True, Encrypt data/messages using symmetric ciphers with passphrases
        - Decryption, True, Decrypt data/messages using symmetric ciphers with passphrases


.. progress:: RFC 4398
    :text: :rfc:`4398` covers publishing and retrieving PGP public keys via DNS CERT records.

    :Key Sources:
        - DNS CERT, False, Look up and retrieve keys stored in Content-based DNS CERT records
        - DNS CERT, False, Look up and retrieve keys stored in Purpose-based DNS CERT records


.. progress:: RFC 5581
    :text: :rfc:`5881` extends RFC 4880 to officially add support for the Camellia cipher

    :Actions:
        - Encryption, True, Camellia*
        - Decryption, True, Camellia*


.. progress:: RFC 6637
    :text: :rfc:`6637` extends OpenPGP to officially add support for elliptic curve cryptography

    :Key Types:
        - ECDH,  False, Elliptic Curve Diffie-Hellman
        - ECDSA, False, Elliptic Curve Digital Signature Algorithm

    :Curves:
        - Curve, False, NIST P-256
        - Curve, False, NIST P-386
        - Curve, False, NIST P-521

    :ECDH Key Actions:
        - Load,       False, Load Keys
        - Generate,   False, Generate Keys
        - Generate,   False, Generate Subkeys
        - KDF,        False, Encode KDF data for encryption
        - KDF,        False, Decode KDF data for decryption

    :ECDSA Key Actions:
        - Load,       False, Load Keys
        - Generate,   False, Generate Keys
        - Generate,   False, Generate Subkeys
        - Sign,       False, Generate detached signatures of binary documents
        - Sign,       False, Generate inline signatures of canonical documents
        - Sign,       False, One-Pass Sign messages
        - Sign,       False, Sign messages
        - Sign,       False, Sign keys
        - Sign,       False, Certify User IDs
        - Sign,       False, Certify User Attributes
        - Sign,       False, Generate key binding signatures
        - Sign,       False, Revoke certifications
        - Sign,       False, Revoke keys
        - Sign,       False, Revoke subkeys
        - Sign,       False, Generate timestamp signatures
        - Sign,       False, Generate standalone signatures
        - Sign,       False, Generate third party confirmation signatures
        - Verify,     False, Verify detached signatures
        - Verify,     False, Verify inline signatures of canonical documents
        - Verify,     False, Verify messages
        - Verify,     False, Verify key signatures
        - Verify,     False, Verify User ID certification signatures
        - Verify,     False, Verify User Attribute certification signatures
        - Verify,     False, Verify key binding signatures
        - Verify,     False, Verify key revocation signatures
        - Verify,     False, Verify subkey revocation signatures
        - Verify,     False, Verify certification revocation signatures
        - Verify,     False, Verify timestamp signatures
        - Verify,     False, Verify standalone signatures
        - Verify,     False, Verify third party confirmation signatures
        - Revocation, False, Designate Revocation Key
        - Revocation, False, Revoke (Sub)Key with Self Signature
        - Revocation, False, Revoke (Sub)Key using Designated Revocation Key

Non-RFC Extensions
==================

.. progress:: DNS PKA
    :text: This section covers things that are considered extensions to PGP, but are not codified in the form of an RFC.

    :Other Sources:
        - DNS PKA, False, Look up and retrieve keys stored in DNS PKA records.


.. note::

    \* Cipher availability depends on the currently installed OpenSSL being compiled with support for it
