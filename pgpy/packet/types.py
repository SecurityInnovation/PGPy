""" types.py
"""
from enum import IntEnum
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms

from ..util import int_to_bytes
from ..errors import WontImplementError


class PFIntEnum(IntEnum):
    def __bytes__(self):
        return int_to_bytes(self.value)


class PubKeyAlgo(PFIntEnum):
    Invalid = 0x00
    RSAEncryptOrSign = 0x01
    RSAEncrypt = 0x02
    RSASign = 0x03
    ElGamal = 0x10
    DSA = 0x11

    def __str__(self):
        if self == PubKeyAlgo.RSAEncryptOrSign:
            return "RSA Encrypt or Sign"

        if self == PubKeyAlgo.ElGamal:
            return "ElGamal Encrypt-Only"

        if self == PubKeyAlgo.DSA:
            return "DSA Digital Signature Algorithm"

        ##TODO: do the rest of these
        raise NotImplementedError(self.name)  # pragma: no cover


class SymmetricKeyAlgo(PFIntEnum):
    Plaintext = 0x00
    IDEA = 0x01
    TripleDES = 0x02
    CAST5 = 0x03
    Blowfish = 0x04
    AES128 = 0x07
    AES192 = 0x08
    AES256 = 0x09
    Twofish256 = 0x0A
    Camellia128 = 0x0B
    Camellia192 = 0x0C
    Camellia256 = 0x0D

    @property
    def block_size(self):
        if self in [SymmetricKeyAlgo.IDEA,
                    SymmetricKeyAlgo.CAST5,
                    SymmetricKeyAlgo.TripleDES,
                    SymmetricKeyAlgo.Blowfish]:
            return 64

        if self in [SymmetricKeyAlgo.AES128,
                    SymmetricKeyAlgo.AES192,
                    SymmetricKeyAlgo.AES256,
                    SymmetricKeyAlgo.Camellia128,
                    SymmetricKeyAlgo.Camellia192,
                    SymmetricKeyAlgo.Camellia256,
                    SymmetricKeyAlgo.Twofish256]:
            return 128

        raise NotImplementedError(self.name)

    @property
    def keylen(self):
        if self in [SymmetricKeyAlgo.IDEA,
                    SymmetricKeyAlgo.CAST5,
                    SymmetricKeyAlgo.AES128,
                    SymmetricKeyAlgo.Camellia128,
                    SymmetricKeyAlgo.Blowfish]:
            return 128

        if self in [SymmetricKeyAlgo.AES192,
                    SymmetricKeyAlgo.Camellia192,
                    SymmetricKeyAlgo.TripleDES]:
            return 192

        if self in [SymmetricKeyAlgo.AES256,
                    SymmetricKeyAlgo.Camellia256,
                    SymmetricKeyAlgo.Twofish256]:
            return 256

        raise NotImplementedError(self.name)  # pragma: no cover

    @property
    def decalg(self):
        if self == SymmetricKeyAlgo.IDEA:
            return algorithms.IDEA

        if self == SymmetricKeyAlgo.TripleDES:
            return algorithms.TripleDES

        if self == SymmetricKeyAlgo.CAST5:
            return algorithms.CAST5

        if self == SymmetricKeyAlgo.Blowfish:
            return algorithms.Blowfish

        if self in [SymmetricKeyAlgo.AES128,
                    SymmetricKeyAlgo.AES192,
                    SymmetricKeyAlgo.AES256]:
            return algorithms.AES

        if self in [SymmetricKeyAlgo.Camellia128,
                    SymmetricKeyAlgo.Camellia192,
                    SymmetricKeyAlgo.Camellia256]:
            return algorithms.Camellia

        raise NotImplementedError(self.name)

    @property
    def encalg(self):
        # encryption cipher
        pass

    def __str__(self):
        if self in [SymmetricKeyAlgo.CAST5,
                    SymmetricKeyAlgo.Blowfish,
                    SymmetricKeyAlgo.IDEA]:
            return self.name

        if self == SymmetricKeyAlgo.TripleDES:
            return "Triple-DES"

        if self == SymmetricKeyAlgo.Twofish256:
            return "Twofish with 256-bit key"

        if self in [SymmetricKeyAlgo.AES128,
                    SymmetricKeyAlgo.AES192,
                    SymmetricKeyAlgo.AES256]:
            return "AES with {keysize}-bit key".format(keysize=self.name[-3:])

        if self in [SymmetricKeyAlgo.Camellia128,
                    SymmetricKeyAlgo.Camellia192,
                    SymmetricKeyAlgo.Camellia256]:
            return "Camellia with {keysize}-bit key".format(keysize=self.name[-3:])

        raise NotImplementedError(self.name)  # pragma: no cover


class CompressionAlgo(PFIntEnum):
    Uncompressed = 0x00
    ZIP = 0x01
    ZLIB = 0x02
    BZ2 = 0x03

    def __str__(self):
        if self == CompressionAlgo.Uncompressed:
            return "Uncompressed"

        if self == CompressionAlgo.ZIP:
            return "ZIP <RFC1951>"

        if self == CompressionAlgo.ZLIB:
            return "ZLIB <RFC1950>"

        if self == CompressionAlgo.BZ2:
            return "BZip2"

        raise NotImplementedError(self.name)  # pragma: no cover


class HashAlgo(PFIntEnum):
    Invalid = 0x00
    MD5 = 0x01
    SHA1 = 0x02
    RIPEMD160 = 0x03
    SHA256 = 0x08
    SHA384 = 0x09
    SHA512 = 0x0A
    SHA224 = 0x0B

    @property
    def digestlen(self):
        if self == HashAlgo.SHA1:
            return 160

        raise NotImplementedError(self.name)  # pragma: no cover

    @property
    def hasher(self):
        if self == HashAlgo.MD5:
            return hashes.MD5()

        if self == HashAlgo.SHA1:
            return hashes.SHA1()

        if self == HashAlgo.RIPEMD160:
            return hashes.RIPEMD160()

        if self == HashAlgo.SHA256:
            return hashes.SHA256()

        if self == HashAlgo.SHA384:
            return hashes.SHA384()

        if self == HashAlgo.SHA512:
            return hashes.SHA512()

        if self == HashAlgo.SHA224:
            return hashes.SHA224()

        raise NotImplementedError(self.name)

    def __str__(self):
        return self.name


class PacketField(object):
    def __init__(self, packet=None):
        if packet is not None:
            self.parse(packet)

    def parse(self, packet):
        """
        :param packet: raw packet bytes
        """
        raise NotImplementedError()  # pragma: no cover

    def __bytes__(self):
        raise NotImplementedError()  # pragma: no cover
