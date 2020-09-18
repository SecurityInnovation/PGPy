Constants
=========

.. py:currentmodule:: pgpy.constants

:py:class:`PubKeyAlgorithm`
---------------------------

.. autoclass:: PubKeyAlgorithm
    :no-members:

    .. autoattribute:: RSAEncryptOrSign
        :annotation:

    .. autoattribute:: DSA
        :annotation:

    .. autoattribute:: ElGamal
        :annotation:

    .. autoattribute:: ECDH
        :annotation:

    .. autoattribute:: ECDSA
        :annotation:

:py:class:`EllipticCurveOID`
----------------------------

.. autoclass:: EllipticCurveOID
    :no-members:

    .. autoattribute:: Curve25519
        :annotation:

    .. autoattribute:: Ed25519
        :annotation:

    .. autoattribute:: NIST_P256
        :annotation:

    .. autoattribute:: NIST_P384
        :annotation:

    .. autoattribute:: NIST_P521
        :annotation:

    .. autoattribute:: Brainpool_P256
        :annotation:

    .. autoattribute:: Brainpool_P384
        :annotation:

    .. autoattribute:: Brainpool_P512
        :annotation:

    .. autoattribute:: SECP256K1
        :annotation:


:py:class:`SymmetricKeyAlgorithm`
---------------------------------

.. autoclass:: SymmetricKeyAlgorithm
    :no-members:

    .. autoattribute:: IDEA
        :annotation:

    .. autoattribute:: TripleDES
        :annotation:

    .. autoattribute:: CAST5
        :annotation:

    .. autoattribute:: Blowfish
        :annotation:

    .. autoattribute:: AES128
        :annotation:

    .. autoattribute:: AES192
        :annotation:

    .. autoattribute:: AES256
        :annotation:

    .. autoattribute:: Camellia128
        :annotation:

    .. autoattribute:: Camellia192
        :annotation:

    .. autoattribute:: Camellia256
        :annotation:


:py:class:`CompressionAlgorithm`
--------------------------------

.. autoclass:: CompressionAlgorithm
    :no-members:

    .. autoattribute:: Uncompressed
        :annotation:

    .. autoattribute:: ZIP
        :annotation:

    .. autoattribute:: ZLIB
        :annotation:

    .. autoattribute:: BZ2
        :annotation:

:py:class:`HashAlgorithm`
-------------------------

.. autoclass:: HashAlgorithm()
    :no-members:

    .. autoattribute:: MD5
        :annotation:

    .. autoattribute:: SHA1
        :annotation:

    .. autoattribute:: RIPEMD160
        :annotation:

    .. autoattribute:: SHA256
        :annotation:

    .. autoattribute:: SHA384
        :annotation:

    .. autoattribute:: SHA512
        :annotation:

    .. autoattribute:: SHA224
        :annotation:


:py:class:`SignatureType`
-------------------------

.. autoclass:: SignatureType
    :no-members:

    .. autoattribute:: BinaryDocument
        :annotation:

    .. autoattribute:: CanonicalDocument
        :annotation:

    .. autoattribute:: Standalone
        :annotation:

    .. autoattribute:: Generic_Cert
        :annotation:

    .. autoattribute:: Persona_Cert
        :annotation:

    .. autoattribute:: Casual_Cert
        :annotation:

    .. autoattribute:: Positive_Cert
        :annotation:

    .. autoattribute:: Attestation
        :annotation:

    .. autoattribute:: Subkey_Binding
        :annotation:

    .. autoattribute:: PrimaryKey_Binding
        :annotation:

    .. autoattribute:: DirectlyOnKey
        :annotation:

    .. autoattribute:: KeyRevocation
        :annotation:

    .. autoattribute:: SubkeyRevocation
        :annotation:

    .. autoattribute:: CertRevocation
        :annotation:

    .. autoattribute:: Timestamp
        :annotation:

    .. autoattribute:: ThirdParty_Confirmation
        :annotation:


:py:class:`KeyFlags`
--------------------

.. autoclass:: KeyFlags
    :no-members:

    .. autoattribute:: Certify
        :annotation:

    .. autoattribute:: Sign
        :annotation:

    .. autoattribute:: EncryptCommunications
        :annotation:

    .. autoattribute:: EncryptStorage
        :annotation:

    .. autoattribute:: Split
        :annotation:

    .. autoattribute:: Authentication
        :annotation:

    .. autoattribute:: MultiPerson
        :annotation:


:py:class:`RevocationReason`
----------------------------

.. autoclass:: RevocationReason
    :no-members:

    .. autoattribute:: NotSpecified
        :annotation:

    .. autoattribute:: Superseded
        :annotation:

    .. autoattribute:: Compromised
        :annotation:

    .. autoattribute:: Retired
        :annotation:

    .. autoattribute:: UserID
        :annotation:

