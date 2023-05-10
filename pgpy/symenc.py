""" symenc.py
"""

from typing import Optional, Union

from cryptography.exceptions import UnsupportedAlgorithm

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers.aead import AESOCB3, AESGCM

from .constants import AEADMode, SymmetricKeyAlgorithm

from .errors import PGPDecryptionError
from .errors import PGPEncryptionError
from .errors import PGPInsecureCipherError

__all__ = ['_cfb_encrypt',
           '_cfb_decrypt',
           'AEAD']


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


class AEAD:
    def __init__(self, cipher: SymmetricKeyAlgorithm, mode: AEADMode, key: bytes) -> None:
        self._aead: Union[AESOCB3, AESGCM]
        if cipher not in [SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES256]:
            raise NotImplementedError(f"Cannot do AEAD with non-AES cipher (requested cipher: {cipher!r})")
        if mode == AEADMode.OCB:
            self._aead = AESOCB3(key)
        elif mode == AEADMode.GCM:
            self._aead = AESGCM(key)
        else:
            raise NotImplementedError(f"Cannot do AEAD mode other than OCB, and GCM (requested mode: {mode!r})")

    def encrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        return self._aead.encrypt(nonce, data, associated_data)

    def decrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        return self._aead.decrypt(nonce, data, associated_data)
