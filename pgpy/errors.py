""" errors.py
"""


class PGPError(Exception):
    """Raised as a general error in PGPy"""
    pass


class PGPKeyDecryptionError(Exception):
    """Raised when decryption fails"""
    pass

class PGPOpenSSLCipherNotSupported(Exception):
    """Raised when OpenSSL does not support the requested cipher"""
    pass


class WontImplementError(NotImplementedError):
    """Raised when something that is not implemented, will not be implemented"""
    pass