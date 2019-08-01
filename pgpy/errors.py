""" errors.py
"""

__all__ = ('PGPError',
           'PGPEncryptionError',
           'PGPDecryptionError',
           'PGPIncompatibleECPointFormat',
           'PGPOpenSSLCipherNotSupported',
           'PGPInsecureCipher',
           'WontImplementError',)


class PGPError(Exception):
    """Raised as a general error in PGPy"""
    pass


class PGPEncryptionError(Exception):
    """Raised when encryption fails"""
    pass


class PGPDecryptionError(Exception):
    """Raised when decryption fails"""
    pass


class PGPIncompatibleECPointFormat(Exception):
    """Raised when the point format is incompatible with the elliptic curve"""
    pass


class PGPOpenSSLCipherNotSupported(Exception):
    """Raised when OpenSSL does not support the requested cipher"""
    pass


class PGPInsecureCipher(Exception):
    """Raised when a cipher known to be insecure is attempted to be used to encrypt data"""
    pass


class WontImplementError(NotImplementedError):
    """Raised when something that is not implemented, will not be implemented"""
    pass
