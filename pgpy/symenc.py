""" symenc.py
"""
import six

from cryptography.exceptions import UnsupportedAlgorithm

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes

from .errors import PGPDecryptionError


def _encrypt(pt, key, alg, iv, real_iv=False):
    raise NotImplementedError()


def _decrypt(ct, key, alg, iv=None):
    # when decrypting secret key material, standard CFB is used with a normal IV
    if iv is not None:
        mode = modes.CFB(iv)

    # otherwise, OpenPGP CFB mode is used
    else:
        """
        Instead of using an IV, OpenPGP prefixes a string of length
        equal to the block size of the cipher plus two to the data before it
        is encrypted. The first block-size octets (for example, 8 octets for
        a 64-bit block length) are random, and the following two octets are
        copies of the last two octets of the IV.
        """
        mode = modes.CFB(b'\x00' * (alg.block_size // 8))

    try:
        decryptor = Cipher(alg.cipher(key), mode, default_backend()).decryptor()

    except UnsupportedAlgorithm as ex:
        six.reraise(PGPDecryptionError, ex)

    return bytearray(decryptor.update(ct) + decryptor.finalize())
