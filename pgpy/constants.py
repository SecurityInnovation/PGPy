""" constants.py
"""
import bz2
import hashlib
import struct
import zlib

from collections import namedtuple
from enum import IntEnum

from cryptography.hazmat.primitives.ciphers import algorithms

from .types import FlagEnum


class PacketTag(IntEnum):
    PublicKeyEncryptedSessionKey = 1
    Signature = 2
    SymmetricKeyEncryptedSessionKey = 3
    OnePassSignature = 4
    SecretKey = 5
    PublicKey = 6
    SecretSubKey = 7
    CompressedData = 8
    SymmetricallyEncryptedData = 9
    Marker = 10
    LiteralData = 11
    Trust = 12
    UserID = 13
    PublicSubKey = 14
    UserAttribute = 17
    SymmetricallyEncryptedIntegrityProtectedData = 18
    ModificationDetectionCode = 19


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
    def cipher(self):
        bs = {SymmetricKeyAlgorithm.IDEA: algorithms.IDEA,
              SymmetricKeyAlgorithm.TripleDES: algorithms.TripleDES,
              SymmetricKeyAlgorithm.CAST5: algorithms.CAST5,
              SymmetricKeyAlgorithm.Blowfish: algorithms.Blowfish,
              SymmetricKeyAlgorithm.AES128: algorithms.AES,
              SymmetricKeyAlgorithm.AES192: algorithms.AES,
              SymmetricKeyAlgorithm.AES256: algorithms.AES,
              SymmetricKeyAlgorithm.Twofish256: namedtuple('Twofish256', ['block_size'])(block_size=128),
              SymmetricKeyAlgorithm.Camellia128: algorithms.Camellia,
              SymmetricKeyAlgorithm.Camellia192: algorithms.Camellia,
              SymmetricKeyAlgorithm.Camellia256: algorithms.Camellia}

        if self in bs:
            return bs[self]

        raise NotImplementedError(repr(self))

    @property
    def block_size(self):
        return self.cipher.block_size

    @property
    def key_size(self):
        ks = {SymmetricKeyAlgorithm.IDEA: 128,
              SymmetricKeyAlgorithm.TripleDES: 192,
              SymmetricKeyAlgorithm.CAST5: 128,
              SymmetricKeyAlgorithm.Blowfish: 128,
              SymmetricKeyAlgorithm.AES128: 128,
              SymmetricKeyAlgorithm.AES192: 192,
              SymmetricKeyAlgorithm.AES256: 256,
              SymmetricKeyAlgorithm.Twofish256: 256,
              SymmetricKeyAlgorithm.Camellia128: 128,
              SymmetricKeyAlgorithm.Camellia192: 192,
              SymmetricKeyAlgorithm.Camellia256: 256}

        if self in ks:
            return ks[self]

        raise NotImplementedError(repr(self))


class PubKeyAlgorithm(IntEnum):
    Invalid = 0x00
    RSAEncryptOrSign = 0x01
    RSAEncrypt = 0x02  # deprecated
    RSASign = 0x03     # deprecated
    ElGamal = 0x10
    DSA = 0x11
    # EllipticCurve = 0x12
    # ECDSA = 0x13
    FormerlyElGamalEncryptOrSign = 0x14  # deprecated - do not generate
    # DiffieHellman = 0x15  # X9.42


class CompressionAlgorithm(IntEnum):
    Uncompressed = 0x00
    ZIP = 0x01
    ZLIB = 0x02
    BZ2 = 0x03

    def compress(self, data):
        if self is CompressionAlgorithm.Uncompressed:
            return data

        if self is CompressionAlgorithm.ZIP:
            return zlib.compress(data)[2:-4]

        if self is CompressionAlgorithm.ZLIB:
            return zlib.compress(data)

        if self is CompressionAlgorithm.BZ2:
            return bz2.compress(data)

        raise NotImplementedError(self)

    def decompress(self, data):
        if self is CompressionAlgorithm.Uncompressed:
            return data

        if self is CompressionAlgorithm.ZIP:
            return zlib.decompress(data, -15)

        if self is CompressionAlgorithm.ZLIB:
            return zlib.decompress(data)

        if self is CompressionAlgorithm.BZ2:
            return bz2.decompress(data)

        raise NotImplementedError(self)


class HashAlgorithm(IntEnum):
    Invalid = 0x00
    MD5 = 0x01
    SHA1 = 0x02
    RIPEMD160 = 0x03
    _reserved_1 = 0x04
    _reserved_2 = 0x05
    _reserved_3 = 0x06
    _reserved_4 = 0x07
    SHA256 = 0x08
    SHA384 = 0x09
    SHA512 = 0x0A
    SHA224 = 0x0B

    @property
    def hasher(self):
        return hashlib.new(self.name)

    @property
    def digest_size(self):
        return self.hasher.digest_size


class RevocationReason(IntEnum):
    NotSpecified = 0x00
    Superseded = 0x01
    Compromised = 0x02
    Retired = 0x03
    UserID = 0x20


class ImageEncoding(IntEnum):
    Unknown = 0x00
    JPEG = 0x01


class SignatureType(IntEnum):
    BinaryDocument = 0x00
    CanonicalDocument = 0x01
    Standalone = 0x02
    Generic_Cert = 0x10
    Persona_Cert = 0x11
    Casual_Cert = 0x12
    Positive_Cert = 0x13
    Subkey_Binding = 0x18
    PrimaryKey_Binding = 0x19
    DirectlyOnKey = 0x1F
    KeyRevocation = 0x20
    SubkeyRevocation = 0x28
    CertRevocation = 0x30
    Timestamp = 0x40
    ThirdParty_Confirmation = 0x50


class KeyServerPreferences(IntEnum):
    Unknown = 0x00
    NoModify = 0x80


class String2KeyType(IntEnum):
    Simple = 0
    Salted = 1
    Reserved = 2
    Iterated = 3


class TrustLevel(IntEnum):
    Unknown = 0
    Expired = 1
    Undefined = 2
    Never = 3
    Marginal = 4
    Fully = 5
    Ultiated = 6


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


class TrustFlags(FlagEnum):
    Revoked = 0x20
    SubRevoked = 0x40
    Disabled = 0x80
    PendingCheck = 0x100
