pgpy
====

Constants
---------

.. py:currentmodule:: pgpy.constants

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

    .. autoattribute:: Camellia128
        :annotation:

    .. autoattribute:: Camellia192
        :annotation:

    .. autoattribute:: Camellia256
        :annotation:

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

.. autoclass:: HashAlgorithm
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

    .. autoattribute:: Positive_Cert
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

PGPy Classes
------------

.. py:currentmodule:: pgpy

.. autoclass:: PGPKey
    :members:

.. autoclass:: PGPKeyring
    :members:

.. autoclass:: PGPMessage
    :members:

.. autoclass:: PGPSignature
    :members:

.. autoclass:: PGPUID
    :members:
