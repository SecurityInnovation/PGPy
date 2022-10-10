*******************************
OpenPGP Implementation Progress
*******************************

OpenPGP RFCs
============

PGPy is focused on eventually reaching complete OpenPGP implementation, adhering to the base OpenPGP message format specification, and its extension RFCs.

.. progress:: RFC 4880
    :text: PGPy is currently focused on achieving :rfc:`4880` compliance for OpenPGP, which is the latest complete OpenPGP Message Format specification. It supersedes RFC 1991 and RFC 2440.

    :Versioned Packets, v1:
        - Tag 18, True,  Symmetrically Encrypted and Integrity Protected Data Packet

    :Versioned Packets, v3:
        - Tag 1,  True,  Public-Key Encrypted Session Key Packets
        - Tag 2,  False, Signature Packet
        - Tag 4,  True,  One-Pass Signature Packet
        - Tag 5,  False, Secret-Key Packet
        - Tag 6,  False, Public-Key Packet
        - Tag 7,  False, Secret-Subkey Packet
        - Tag 14, False, Public-SubKey Packet

    :Versioned Packets, v4:
        - Tag 2,  True, Signature Packet
        - Tag 3,  True, Symmetric-Key Encrypted Session Key Packet
        - Tag 5,  True, Secret-Key Packet
        - Tag 6,  True, Public-Key Packet
        - Tag 7,  True, Secret-Subkey Packet
        - Tag 14, True, Public-SubKey Packet

    :Unversioned Packets:
        - Tag 8,  True, Compressed Data Packet
        - Tag 9,  True, Symmetrically Encrypted Data Packet
        - Tag 10, True, Marker Packet
        - Tag 11, True, Literal Data Packet
        - Tag 12, True, Trust Packet
        - Tag 13, True, User ID Packet
        - Tag 17, True, User Attribute Packet
        - Tag 19, True, Modification Detection Code Packet

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
        - 0x1F,  False, Signature Target
        - 0x20,  True,  Embedded Signature

    :User Attribute Subpackets:
        - 0x01, True, Image

    :Storage Formats:
        - ASCII,  True, ASCII armored PGP blocks
        - binary, True, binary PGP packets
        - GPG,    True, GPG <= 2.0.x keyrings
        - KBX,    False, GPG >= 2.1.x keyboxes

    :Other Sources:
        - Retrieve, False, Retrieve from HKP key servers
        - Upload,   False, Submit to HKP key servers

    :Key Types:
        - RSA,     True, RSA
        - DSA,     True, DSA
        - ElGamal, True, ElGamal

    :Key Actions:
        - Protect,   True,  Protect private keys encryped with CAST5
        - Protect,   True,  Protect private keys encryped with Blowfish
        - Protect,   True,  Protect private keys encryped with AES
        - Protect,   False, Protect private keys encryped with Twofish
        - Unprotect, True,  Unprotect private keys encrypted with IDEA [1]_
        - Unprotect, True,  Unprotect private keys encrypted with Triple-DES
        - Unprotect, True,  Unprotect private keys encrypted with CAST5
        - Unprotect, True,  Unprotect private keys encrypted with Blowfish
        - Unprotect, True,  Unprotect private keys encrypted with AES
        - Unprotect, False, Unprotect private keys encrypted with Twofish

    :RSA Key Actions:
        - Load,       True,  Load Keys
        - Generate,   True,  Generate Keys
        - Generate,   True,  Generate Subkeys
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
        - Generate,   True,  Generate Keys
        - Generate,   True,  Generate Subkeys
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
    :text: :rfc:`5581` extends RFC 4880 to officially add support for the Camellia cipher

    :Actions:
        - Encryption, True, Camellia [1]_
        - Decryption, True, Camellia [1]_


.. progress:: RFC 6637
    :text: :rfc:`6637` extends OpenPGP to officially add support for elliptic curve cryptography

    :Key Types:
        - ECDH,  True, Elliptic Curve Diffie-Hellman
        - ECDSA, True, Elliptic Curve Digital Signature Algorithm

    :Curves:
        - Curve, True, NIST P-256
        - Curve, True, NIST P-386
        - Curve, True, NIST P-521

    :ECDH Key Actions:
        - Load,       True,  Load Keys
        - Generate,   True,  Generate Keys
        - Generate,   True,  Generate Subkeys
        - KDF,        True,  Encode KDF data for encryption
        - KDF,        True,  Decode KDF data for decryption

    :ECDSA Key Actions:
        - Load,       True,  Load Keys
        - Generate,   True,  Generate Keys
        - Generate,   True,  Generate Subkeys
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
        - Verify,     True,  Verify Use r ID certification signatures
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

Non-RFC Extensions
==================

This section covers things that are considered extensions to PGP, but are not codified in the form of an RFC.

.. progress:: DNS PKA
    :text: Publishing OpenPGP keys in DNS

    :Other Sources:
        - DNS PKA, False, Look up and retrieve keys stored in DNS PKA records.

.. progress:: OpenPGP HTTP Keyserver Protocol (HKP)
    :text: The protocol is specified in `Marc Horowitz's thesis paper`_, and an expired RFC draft by David Shaw, `draft-shaw-openpgp-hkp-00`_.

    :HKP:
        - Discovery, False, Round robin DNS and SRV lookups (section 7. Locating a HKP Keyserver)
        - Index,     False, Look up keys on key server, with multiple possible matches (section 3.1.2.2. The "index" Operation)
        - Get,       False, Retrieve keys from key server, single fingerprint fetch (section 3.1.2.1. The "get" operation)
        - Post,      False, Send keys to key server (section 4. Submitting Keys To A Keyserver)

.. progress:: OpenPGP Web Key Service (WKS)
    :text: LocatesOpenPGP keys by mail address using a Web service and the HTTPS protocol. Protocol specified in an in-progress RFC draft by Werner Koch, `draft-koch-openpgp-webkey-service`_

    :WKS:
        - Discovery, False, Fetches keys matching a UID from the server, using DNS and SRV lookups (section 3.1.  Key Discovery)
        - Update,    False, Update keys on the WKS (section 4.  Web Key Directory Update Protocol)

.. progress:: EdDSA for OpenPGP
    :text: Use of Ed25519 with ECDSA and ECDH in OpenPGP is currently specified in an in-progress RFC draft by Werner Koch, `draft-ietf-openpgp-rfc4880bis`_.

    :Curves:
        - Curve, True, Ed25519
        - Curve, True, X25519


.. progress:: Additional Curves for OpenPGP
    :text: Some additional curves that can be used with ECDSA/ECDH that are not explicitly called out in :rfc:`6637`, but have standardized OIDs and are implemented in other software.

    :Curves:
        - Curve, True,  Brainpool P-256
        - Curve, True,  Brainpool P-384
        - Curve, True,  Brainpool P-512
        - Curve, True,  Curve25519 [1]_
        - Curve, True,  SECP256K1

.. note::
    Use of Brainpool curves with ECDSA/ECDH

    Although these curves are not explicitly mentioned in an RFC for OpenPGP at this point, GnuPG 2.1.x+ does support
    using them. As such, they have been included here.

.. [1] Cipher availability depends on the currently installed OpenSSL being compiled with support for it


.. _`Marc Horowitz's thesis paper`: http://www.mit.edu/afs/net.mit.edu/project/pks/thesis/paper/thesis.html
.. _`draft-shaw-openpgp-hkp-00`: https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
.. _`draft-koch-openpgp-webkey-service`: https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-04
.. _`draft-ietf-openpgp-rfc4880bis`: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis
