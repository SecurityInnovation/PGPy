""" symenc.py
"""

from typing import Optional, Union
from types import ModuleType

from cryptography.exceptions import UnsupportedAlgorithm

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers.aead import AESOCB3, AESGCM

from .constants import AEADMode, SymmetricKeyAlgorithm

from .errors import PGPDecryptionError
from .errors import PGPEncryptionError
from .errors import PGPInsecureCipherError

AES_Cryptodome: Optional[ModuleType]
try:
    from Cryptodome.Cipher import AES as AES_Cryptodome
except ModuleNotFoundError:
    AES_Cryptodome = None

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
    class AESEAX:
        '''This class supports the same interface as AESOCB3 and AESGCM from python's cryptography module

        We don't use that module because it doesn't support EAX
        (see https://github.com/pyca/cryptography/issues/6903)
        '''

        def __init__(self, key: bytes) -> None:
            self._key: bytes = key

        def decrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
            if AES_Cryptodome is None:
                raise NotImplementedError("AEAD Mode EAX needs the python Cryptodome module installed")
            if len(nonce) != AEADMode.EAX.iv_len:
                raise ValueError(f"EAX nonce should be {AEADMode.EAX.iv_len} octets, got {len(nonce)}")
            a = AES_Cryptodome.new(self._key, AES_Cryptodome.MODE_EAX, nonce, mac_len=AEADMode.EAX.tag_len)
            if associated_data is not None:
                a.update(associated_data)
            return a.decrypt_and_verify(data[:-AEADMode.EAX.tag_len], data[-AEADMode.EAX.tag_len:])

        def encrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
            if AES_Cryptodome is None:
                raise NotImplementedError("AEAD Mode EAX needs the python Cryptodome module installed")
            if len(nonce) != AEADMode.EAX.iv_len:
                raise ValueError(f"EAX nonce should be {AEADMode.EAX.iv_len} octets, got {len(nonce)}")
            a = AES_Cryptodome.new(self._key, AES_Cryptodome.MODE_EAX, nonce, mac_len=AEADMode.EAX.tag_len)
            if associated_data is not None:
                a.update(associated_data)
            ciphertext, tag = a.encrypt_and_digest(data)
            return ciphertext + tag

    def __init__(self, cipher: SymmetricKeyAlgorithm, mode: AEADMode, key: bytes) -> None:
        self._aead: Union[AESOCB3, AESGCM, AEAD.AESEAX]
        if cipher not in [SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES256]:
            raise NotImplementedError(f"Cannot do AEAD with non-AES cipher (requested cipher: {cipher!r})")
        if mode == AEADMode.OCB:
            self._aead = AESOCB3(key)
        elif mode == AEADMode.GCM:
            self._aead = AESGCM(key)
        elif mode == AEADMode.EAX:
            self._aead = AEAD.AESEAX(key)
        else:
            raise NotImplementedError(f"Cannot do AEAD mode other than OCB, GCM, and EAX (requested mode: {mode!r})")

    def encrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        return self._aead.encrypt(nonce, data, associated_data)

    def decrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        return self._aead.decrypt(nonce, data, associated_data)
