""" symenc.py
"""
from cryptography.exceptions import UnsupportedAlgorithm

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes

from .errors import PGPDecryptionError
from .errors import PGPEncryptionError
from .errors import PGPInsecureCipherError

__all__ = ['_encrypt',
           '_decrypt',
           '_encrypt_stream',
           '_decrypt_stream']


def _encrypt(pt, key, alg, iv=None):
    if iv is None:
        iv = b'\x00' * (alg.block_size // 8)

    if alg.is_insecure:
        raise PGPInsecureCipherError("{:s} is not secure. Do not use it for encryption!".format(alg.name))

    if not alg.is_supported:
        raise PGPEncryptionError("Cipher {:s} not supported".format(alg.name))

    try:
        encryptor = Cipher(alg.cipher(key), modes.CFB(iv), default_backend()).encryptor()

    except UnsupportedAlgorithm as ex:  # pragma: no cover
        raise PGPEncryptionError from ex

    else:
        return bytearray(encryptor.update(pt) + encryptor.finalize())


def _decrypt(ct, key, alg, iv=None):
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
        decryptor = Cipher(alg.cipher(key), modes.CFB(iv), default_backend()).decryptor()

    except UnsupportedAlgorithm as ex:  # pragma: no cover
        raise PGPDecryptionError from ex

    else:
        return bytearray(decryptor.update(ct) + decryptor.finalize())


def _encrypt_stream(data_iterator, key, alg, iv=None):
    """
    Encrypt data from an iterator in streaming mode.
    
    :param data_iterator: An iterator yielding bytes/bytearray chunks
    :param key: Encryption key
    :param alg: Symmetric algorithm
    :param iv: Initialization vector (optional)
    :yields: Encrypted data chunks
    """
    if iv is None:
        iv = b'\x00' * (alg.block_size // 8)

    if alg.is_insecure:
        raise PGPInsecureCipherError("{:s} is not secure. Do not use it for encryption!".format(alg.name))

    if not alg.is_supported:
        raise PGPEncryptionError("Cipher {:s} not supported".format(alg.name))

    try:
        encryptor = Cipher(alg.cipher(key), modes.CFB(iv), default_backend()).encryptor()

    except UnsupportedAlgorithm as ex:  # pragma: no cover
        raise PGPEncryptionError from ex

    for chunk in data_iterator:
        if chunk:
            yield bytearray(encryptor.update(bytes(chunk)))
    
    yield bytearray(encryptor.finalize())


def _decrypt_stream(data_iterator, key, alg, iv=None):
    """
    Decrypt data from an iterator in streaming mode.
    
    :param data_iterator: An iterator yielding bytes/bytearray chunks
    :param key: Decryption key
    :param alg: Symmetric algorithm
    :param iv: Initialization vector (optional)
    :yields: Decrypted data chunks
    """
    if iv is None:
        iv = b'\x00' * (alg.block_size // 8)

    try:
        decryptor = Cipher(alg.cipher(key), modes.CFB(iv), default_backend()).decryptor()

    except UnsupportedAlgorithm as ex:  # pragma: no cover
        raise PGPDecryptionError from ex

    for chunk in data_iterator:
        if chunk:
            yield bytearray(decryptor.update(bytes(chunk)))
    
    yield bytearray(decryptor.finalize())
