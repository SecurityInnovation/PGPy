""" constants.py
"""

from enum import IntEnum

from .types import FlagEnum


class SymmetricKeyAlgorithm(IntEnum):
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
    def __name__(self):
        names = {'TripleDES': 'Triple-DES',}
        names.update({ska.name: '{:s} with {:s}-bit key'.format(ska.name[:-3], ska.name[-3:])
                      for ska in SymmetricKeyAlgorithm if ska.name[-3:] in ['128', '192', '256'] })
        if self.name in names:
            return names[self.name]
        return self.name


class PubKeyAlgorithm(IntEnum):
    Invalid = 0x00
    RSAEncryptOrSign = 0x01
    RSAEncrypt = 0x02
    RSASign = 0x03
    ElGamal = 0x10
    DSA = 0x11


class CompressionAlgorithm(IntEnum):
    Uncompressed = 0x00
    ZIP = 0x01
    ZLIB = 0x02
    BZ2 = 0x03


class HashAlgorithm(IntEnum):
    Invalid = 0x00
    MD5 = 0x01
    SHA1 = 0x02
    RIPEMD160 = 0x03
    SHA256 = 0x08
    SHA384 = 0x09
    SHA512 = 0x0A
    SHA224 = 0x0B


class RevocationReason(IntEnum):
    NotSpecified = 0x00
    Superseded = 0x01
    Compromised = 0x02
    Retired = 0x03
    UserID = 0x20


class ImageEncoding(IntEnum):
    Unknown = 0x00
    JPEG = 0x01


class KeyFlags(FlagEnum):
    Certify = 0x01
    Sign = 0x02
    EncryptCommunications = 0x04
    EncryptStorage = 0x08
    Split = 0x10
    Authentication = 0x20
    MultiPerson = 0x80


class Features(FlagEnum):
    ModificationDetection = 0x01


class RevocationKeyClass(FlagEnum):
    Sensitive = 0x40
    Normal = 0x80


class NotationDataFlags(FlagEnum):
    HumanReadable = 0x80


class KeyServerPreferences(FlagEnum):
    NoModify = 0x80
