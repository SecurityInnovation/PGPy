Classes
=======

.. py:currentmodule:: pgpy

:py:class:`PGPKey`
------------------

.. autoclass:: PGPKey
    :members:
    :noindex:

    .. py:classmethod:: from_file(filename)
        :noindex:

    .. py:classmethod:: from_blob(blob)
        :noindex:

:py:class:`PGPKeyring`
----------------------

.. autoclass:: PGPKeyring
    :members:
    :noindex:

:py:class:`PGPMessage`
----------------------

.. autoclass:: PGPMessage
    :members:
    :noindex:

    .. py:classmethod:: from_file(filename)
        :noindex:

    .. py:classmethod:: from_blob(blob)
        :noindex:

:py:class:`PGPSignature`
------------------------

.. autoclass:: PGPSignature
    :members:
    :noindex:

    .. py:classmethod:: from_file(filename)
        :noindex:

    .. py:classmethod:: from_blob(blob)
        :noindex:

:py:class:`PGPUID`
------------------

.. autoclass:: PGPUID
    :members:
    :noindex:

Other Objects
=============

.. py:currentmodule:: pgpy.types

These are objects that are returned during certain operations, but are probably not useful to instantiate directly.

:py:class:`~types.SignatureVerification`
----------------------------------------

.. autoclass:: SignatureVerification
    :members:
    :noindex:

:py:class:`~types.Fingerprint`
------------------------------

.. autoclass:: Fingerprint
    :members:
    :noindex:
