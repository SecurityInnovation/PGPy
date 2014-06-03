"""signature.py
"""


class SignatureVerification(object):
    """
    Returned by :py:meth:`pgpy.PGPKeyring.verify`

    Can be compared directly as a boolean to determine whether or not the specified signature verified.
    """
    def __init__(self):
        self._verified = False

        self.signature = None
        """
        The :py:class:`~pgpy.pgp.PGPSignature` that was used in the verification that returned this
        """
        self.key = None
        """
        The :py:class:`~pgpy.pgp.PGPKey` (if available) that was used to verify the signature
        """
        self.subject = None
        """
        The subject of the verification
        """

    # Python 2
    def __nonzero__(self):
        return self._verified

    # Python 3
    def __bool__(self):
        return self._verified

    def __repr__(self):  # pragma: no cover
        return "SignatureVerification({key}, {verified})".format(verified=str(bool(self)), key=self.key.keyid)
