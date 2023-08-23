""" symenc.py
"""

from typing import Optional

from cryptography.exceptions import UnsupportedAlgorithm

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes

from .constants import SymmetricKeyAlgorithm

from .errors import PGPDecryptionError
from .errors import PGPEncryptionError
from .errors import PGPInsecureCipherError

__all__ = ['_cfb_encrypt',
           '_cfb_decrypt']


def _cfb_encrypt(pt: bytes, key: bytes, alg: SymmetricKeyAlgorithm, iv: Optional[bytes] = None) -> bytearray:
    if iv is None:
        iv = b'\x00' * (alg.block_size // 8)

    if alg.is_insecure:
        raise PGPInsecureCipherError("{:s} is not secure. Do not use it for encryption!".format(alg.name))

    if not alg.is_supported:
        raise PGPEncryptionError("Cipher {:s} not supported".format(alg.name))

    try:
        encryptor = Cipher(alg.cipher(key), modes.CFB(iv)).encryptor()

    except UnsupportedAlgorithm as ex:  # pragma: no cover
        raise PGPEncryptionError from ex

    else:
        return bytearray(encryptor.update(pt) + encryptor.finalize())


def _cfb_decrypt(ct: bytes, key: bytes, alg: SymmetricKeyAlgorithm, iv: Optional[bytes] = None) -> bytearray:
    if iv is None:
        """
        Instead of using an IV, OpenPGP prefixes a string of length
        equal to the block size of the cipher plus two to the data before it
        is encrypted. The first block-size octets (for example, 8 octets for
        a 64-bit block length) are random, and the following two octets are
        copies of the last two octets of the IV.
        """
        iv = b'\x00' * (alg.block_size // 8)

    try:
        decryptor = Cipher(alg.cipher(key), modes.CFB(iv)).decryptor()

    except UnsupportedAlgorithm as ex:  # pragma: no cover
        raise PGPDecryptionError from ex

    else:
        return bytearray(decryptor.update(ct) + decryptor.finalize())
