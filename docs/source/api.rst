PGPy API
========

Exceptions
----------

Exceptions can be referenced by importing ``pgpy.errors``.

.. py:module:: pgpy.errors

.. autoexception:: PGPError
    :noindex:
    :members:

.. autoexception:: PGPKeyDecryptionError
    :noindex:
    :members:

.. autoexception:: PGPOpenSSLCipherNotSupported
    :noindex:
    :members:

Objects
-------

PGPy objects

:py:class:`~pgpy.PGPKeyring`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. py:module:: pgpy

.. autoclass:: PGPKeyring
    :noindex:
    :members:

:py:class:`~pgpy.types.SignatureVerification`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. py:module:: pgpy.types

.. autoclass:: SignatureVerification
    :noindex:

    .. autoinstanceattribute:: SignatureVerification.signature
        :noindex:
        :annotation:

    .. autoinstanceattribute:: SignatureVerification.key
        :noindex:
        :annotation:

    .. autoinstanceattribute:: SignatureVerification.subject
        :noindex:
        :annotation:

:py:class:`~pgpy.pgp.PGPSignature`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. py:module:: pgpy.pgp

.. autoclass:: PGPSignature()
    :noindex:
    :inherited-members: write

    .. py:attribute:: path
        :noindex:

        :type: str, None
        The local path of this signature, if set. Defaults to ``None`` for new signatures.


:py:class:`~pgpy.pgp.PGPKey`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autoclass:: PGPKey()
    :noindex:
    :members:
