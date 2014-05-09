""" PGPy :: Pretty Good Privacy for Python
"""
from ._author import __author__
from ._author import __copyright__
from ._author import __license__
from ._author import __version__
from .errors import PGPError
from .errors import PGPKeyDecryptionError
from .keys import PGPKeyring

__all__ = [__author__,
           __copyright__,
           __license__,
           __version__,
           PGPError,
           PGPKeyDecryptionError,
           PGPKeyring]
