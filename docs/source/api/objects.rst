Objects
-------

.. autosummary::
    :toctree:
    :nosignatures:

    pgpy.PGPKeyring
    pgpy.types.SignatureVerification
    pgpy.pgp.PGPSignature
    pgpy.pgp.PGPKey

.. py:currentmodule:: pgpy

:py:class:`~pgpy.PGPKeyring`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autoclass:: PGPKeyring
    :members:

    .. py:attribute:: __pubkeys__
        :noindex:

        .. versionadded:: 0.2.0

        :type: :py:obj:`collections.ValuesView`

        A ValuesView of all currently loaded public :py:obj:`~pgpy.pgp.PGPKey` objects.

    .. py:attribute:: __privkeys__
        :noindex:

        .. versionadded:: 0.2.0

        :type: :py:obj:`collections.ValuesView`

        A ValuesView of all currently loaded private :py:obj:`~pgpy.pgp.PGPKey` objects.

    .. py:attribute:: __fingerprints__

        .. versionadded:: 0.2.0

        :type: :py:obj:`collections.KeysView`

        A KeysView of all currently loaded fingerprints. Each item is a subclass of ``str`` that ignores whitespace
        when comparing two strings, such that "DEADBEEF" == "DEAD BEEF" is ``True``.


.. py:currentmodule:: pgpy.types

:py:class:`~pgpy.types.SignatureVerification`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autoclass:: SignatureVerification

    .. autoinstanceattribute:: SignatureVerification.signature
        :noindex:
        :annotation:

    .. autoinstanceattribute:: SignatureVerification.key
        :noindex:
        :annotation:

    .. autoinstanceattribute:: SignatureVerification.subject
        :noindex:
        :annotation:

.. py:currentmodule:: pgpy.pgp

:py:class:`~pgpy.pgp.PGPSignature`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autoclass:: PGPSignature()
    :inherited-members: write

    .. py:attribute:: path
        :noindex:

        :type: str, None
        The local path of this signature, if set. Defaults to ``None`` for new signatures.

:py:class:`~pgpy.pgp.PGPKey`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autoclass:: PGPKey()
    :members:
