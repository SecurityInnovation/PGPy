"""signature.py
"""


class SignatureVerification(object):
    """
    Returned by :py:meth:`pgpy.PGPKeyring.verify`. Can be compared directly as a boolean to determine whether
    or not the specified signature verified.

    .. py:attribute:: signature

        Reference to the signature that was verified.

    .. py:attribute:: key

        Reference to the key used to verify a signature.

    .. py:attribute:: subject

        Reference to the subject that was verified
    """
    def __init__(self):
        self.signature = None
        self.key = None
        self.subject = None

        self.verified = False

    # Python 2
    def __nonzero__(self):
        return self.verified

    # Python 3
    def __bool__(self):
        return self.verified

    def __repr__(self):  # pragma: no cover
        return "SignatureVerification({key}, {verified})".format(verified=str(bool(self)), key=self.key.keyid)