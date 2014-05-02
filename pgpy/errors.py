""" errors.py
"""


class PGPError(Exception):
    """
    Raised as a general error in PGPy.
    """
    pass


class PGPKeyDecryptionError(Exception):
    pass


class WontImplementError(NotImplementedError):
    pass