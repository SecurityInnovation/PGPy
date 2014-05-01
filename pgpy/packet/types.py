""" types.py
"""
from enum import IntEnum

from ..util import int_to_bytes


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
        raise NotImplementedError(self.name)


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

    def __str__(self):
        if self == SymmetricKeyAlgo.TripleDES:
            return "Triple-DES"

        if self == SymmetricKeyAlgo.CAST5:
            return "CAST5"

        if self == SymmetricKeyAlgo.AES128:
            return "AES with 128-bit key"

        if self == SymmetricKeyAlgo.AES192:
            return "AES with 192-bit key"

        if self == SymmetricKeyAlgo.AES256:
            return "AES with 256-bit key"

        raise NotImplementedError(self.name)

    def block_size(self):
        if self == SymmetricKeyAlgo.CAST5:
            return 64

        raise NotImplementedError(self.name)

    def keylen(self):
        if self == SymmetricKeyAlgo.CAST5:
            return 128

        raise NotImplementedError(self.name)


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

        raise NotImplementedError(self.name)


class HashAlgo(PFIntEnum):
    Invalid = 0x00
    MD5 = 0x01
    SHA1 = 0x02
    RIPEMD160 = 0x03
    SHA256 = 0x08
    SHA384 = 0x09
    SHA512 = 0x0A
    SHA224 = 0x0B

    def __str__(self):
        return self.name

    def digestlen(self):
        if self == HashAlgo.SHA1:
            return 160

        raise NotImplementedError()


class PacketField(object):
    def __init__(self, packet=None):
        if packet is not None:
            self.parse(packet)

    def parse(self, packet):
        """
        :param packet: raw packet bytes
        """
        raise NotImplementedError()

    def __bytes__(self):
        raise NotImplementedError()