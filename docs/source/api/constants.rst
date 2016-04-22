Constants
=========

.. py:currentmodule:: pgpy.constants

:py:class:`PubKeyAlgorithm`
---------------------------

.. autoclass:: PubKeyAlgorithm
    :no-members:
    :noindex:

    .. autoattribute:: RSAEncryptOrSign
        :noindex:
        :annotation:

    .. autoattribute:: DSA
        :noindex:
        :annotation:

    .. autoattribute:: ElGamal
        :noindex:
        :annotation:

    .. autoattribute:: ECDH
        :noindex:
        :annotation:

    .. autoattribute:: ECDSA
        :noindex:
        :annotation:

:py:class:`EllipticCurveOID`
----------------------------

.. autoclass:: EllipticCurveOID
    :noindex:

    .. autoattribute:: Curve25519
        :noindex:
        :annotation:

    .. autoattribute:: Ed25519
        :noindex:
        :annotation:

    .. autoattribute:: NIST_P256
        :noindex:
        :annotation:

    .. autoattribute:: NIST_P384
        :noindex:
        :annotation:

    .. autoattribute:: NIST_P521
        :noindex:
        :annotation:

    .. autoattribute:: Brainpool_P256
        :noindex:
        :annotation:

    .. autoattribute:: Brainpool_P384
        :noindex:
        :annotation:

    .. autoattribute:: Brainpool_P512
        :noindex:
        :annotation:

    .. autoattribute:: SECP256K1
        :noindex:
        :annotation:


:py:class:`SymmetricKeyAlgorithm`
---------------------------------

.. autoclass:: SymmetricKeyAlgorithm
    :no-members:
    :noindex:

    .. autoattribute:: IDEA
        :noindex:
        :annotation:

    .. autoattribute:: TripleDES
        :noindex:
        :annotation:

    .. autoattribute:: CAST5
        :noindex:
        :annotation:

    .. autoattribute:: Blowfish
        :noindex:
        :annotation:

    .. autoattribute:: AES128
        :noindex:
        :annotation:

    .. autoattribute:: Camellia128
        :noindex:
        :annotation:

    .. autoattribute:: Camellia192
        :noindex:
        :annotation:

    .. autoattribute:: Camellia256
        :noindex:
        :annotation:


:py:class:`CompressionAlgorithm`
--------------------------------

.. autoclass:: CompressionAlgorithm
    :no-members:
    :noindex:

    .. autoattribute:: Uncompressed
        :noindex:
        :annotation:

    .. autoattribute:: ZIP
        :noindex:
        :annotation:

    .. autoattribute:: ZLIB
        :noindex:
        :annotation:

    .. autoattribute:: BZ2
        :noindex:
        :annotation:

:py:class:`HashAlgorithm`
-------------------------

.. autoclass:: HashAlgorithm
    :no-members:
    :noindex:

    .. autoattribute:: MD5
        :noindex:
        :annotation:

    .. autoattribute:: SHA1
        :noindex:
        :annotation:

    .. autoattribute:: RIPEMD160
        :noindex:
        :annotation:

    .. autoattribute:: SHA256
        :noindex:
        :annotation:

    .. autoattribute:: SHA384
        :noindex:
        :annotation:

    .. autoattribute:: SHA512
        :noindex:
        :annotation:

    .. autoattribute:: SHA224
        :noindex:
        :annotation:


:py:class:`SignatureType`
-------------------------

.. autoclass:: SignatureType
    :no-members:
    :noindex:

    .. autoattribute:: BinaryDocument
        :noindex:
        :annotation:

    .. autoattribute:: CanonicalDocument
        :noindex:
        :annotation:

    .. autoattribute:: Standalone
        :noindex:
        :annotation:

    .. autoattribute:: Generic_Cert
        :noindex:
        :annotation:

    .. autoattribute:: Persona_Cert
        :noindex:
        :annotation:

    .. autoattribute:: Positive_Cert
        :noindex:
        :annotation:

    .. autoattribute:: Subkey_Binding
        :noindex:
        :annotation:

    .. autoattribute:: PrimaryKey_Binding
        :noindex:
        :annotation:

    .. autoattribute:: DirectlyOnKey
        :noindex:
        :annotation:

    .. autoattribute:: KeyRevocation
        :noindex:
        :annotation:

    .. autoattribute:: SubkeyRevocation
        :noindex:
        :annotation:

    .. autoattribute:: CertRevocation
        :noindex:
        :annotation:

    .. autoattribute:: Timestamp
        :noindex:
        :annotation:

    .. autoattribute:: ThirdParty_Confirmation
        :noindex:
        :annotation:


:py:class:`KeyFlags`
--------------------

.. autoclass:: KeyFlags
    :no-members:
    :noindex:

    .. autoattribute:: Certify
        :noindex:
        :annotation:

    .. autoattribute:: Sign
        :noindex:
        :annotation:

    .. autoattribute:: EncryptCommunications
        :noindex:
        :annotation:

    .. autoattribute:: EncryptStorage
        :noindex:
        :annotation:

    .. autoattribute:: Split
        :noindex:
        :annotation:

    .. autoattribute:: Authentication
        :noindex:
        :annotation:

    .. autoattribute:: MultiPerson
        :noindex:
        :annotation:


:py:class:`RevocationReason`
----------------------------

.. autoclass:: RevocationReason
    :no-members:
    :noindex:

    .. autoattribute:: NotSpecified
        :noindex:
        :annotation:

    .. autoattribute:: Superseded
        :noindex:
        :annotation:

    .. autoattribute:: Compromised
        :noindex:
        :annotation:

    .. autoattribute:: Retired
        :noindex:
        :annotation:

    .. autoattribute:: UserID
        :noindex:
        :annotation:

