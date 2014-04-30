"""signature.py
"""

class SignatureVerification(object):
    def __init__(self):
        self.signature = None
        self.key = None
        self.subject = None
        self.message = ""

        self.verified = False

    # Python 2
    def __nonzero__(self):
        return self.verified

    # Python 3
    def __bool__(self):
        return self.verified

    def __repr__(self):
        return "SignatureVerification({key}, {verified}, {message})".format(
            verified=str(bool(self)),
            key=self.key.keyid,
            message=self.message
        )