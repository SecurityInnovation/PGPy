""" constants.py
"""
from __future__ import annotations

import bz2
import os
import zlib
import warnings

from collections import namedtuple
from enum import Enum
from enum import IntEnum
from enum import IntFlag

from typing import NamedTuple, Optional, Type, Union

from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.asymmetric import ec, x25519, ed25519
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives._cipheralgorithm import CipherAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._cipheralgorithm import CipherAlgorithm

from .decorators import classproperty

__all__ = [
    'ECFields',
    'EllipticCurveOID',
    'ECPointFormat',
    'PacketType',
    'SymmetricKeyAlgorithm',
    'PubKeyAlgorithm',
    'CompressionAlgorithm',
    'HashAlgorithm',
    'RevocationReason',
    'SigSubpacketType',
    'AttributeType',
    'ImageEncoding',
    'SignatureType',
    'KeyServerPreferences',
    'S2KGNUExtension',
    'S2KUsage',
    'SecurityIssues',
    'String2KeyType',
    'TrustLevel',
    'KeyFlags',
    'Features',
    'RevocationKeyClass',
    'NotationDataFlags',
    'TrustFlags',
]


# this is 50 KiB
_hashtunedata = bytearray([10, 11, 12, 13, 14, 15, 16, 17] * 128 * 50)


class ECPointFormat(IntEnum):
    # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07#appendix-B
    Standard = 0x04
    Native = 0x40
    OnlyX = 0x41
    OnlyY = 0x42


class PacketType(IntEnum):
    Unknown = -1
    Invalid = 0
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

    @classmethod
    def _missing_(cls, val: object) -> PacketType:
        if not isinstance(val, int):
            raise TypeError(f"cannot look up PacketType by non-int {type(val)}")
        return cls.Unknown


class SymmetricKeyAlgorithm(IntEnum):
    """Supported symmetric key algorithms."""
    Plaintext = 0x00
    #: .. warning:: IDEA is insecure. PGPy only allows it to be used for decryption, not encryption!
    IDEA = 0x01
    #: Triple-DES with 168-bit key derived from 192
    TripleDES = 0x02
    #: CAST5 (or CAST-128) with 128-bit key
    CAST5 = 0x03
    #: Blowfish with 128-bit key and 16 rounds
    Blowfish = 0x04
    #: AES with 128-bit key
    AES128 = 0x07
    #: AES with 192-bit key
    AES192 = 0x08
    #: AES with 256-bit key
    AES256 = 0x09
    # Twofish with 256-bit key - not currently supported
    Twofish256 = 0x0A
    #: Camellia with 128-bit key
    Camellia128 = 0x0B
    #: Camellia with 192-bit key
    Camellia192 = 0x0C
    #: Camellia with 256-bit key
    Camellia256 = 0x0D

    def cipher(self, key: bytes) -> CipherAlgorithm:
        if self is SymmetricKeyAlgorithm.IDEA:
            return algorithms.IDEA(key)
        elif self is SymmetricKeyAlgorithm.TripleDES:
            return algorithms.TripleDES(key)
        elif self is SymmetricKeyAlgorithm.CAST5:
            return algorithms.CAST5(key)
        elif self is SymmetricKeyAlgorithm.Blowfish:
            return algorithms.Blowfish(key)
        elif self in {SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES256}:
            return algorithms.AES(key)
        elif self in {SymmetricKeyAlgorithm.Camellia128, SymmetricKeyAlgorithm.Camellia192, SymmetricKeyAlgorithm.Camellia256}:
            return algorithms.Camellia(key)
        raise NotImplementedError(repr(self))

    @property
    def is_supported(self) -> bool:
        return self in {SymmetricKeyAlgorithm.IDEA,
                        SymmetricKeyAlgorithm.TripleDES,
                        SymmetricKeyAlgorithm.CAST5,
                        SymmetricKeyAlgorithm.Blowfish,
                        SymmetricKeyAlgorithm.AES128,
                        SymmetricKeyAlgorithm.AES192,
                        SymmetricKeyAlgorithm.AES256,
                        SymmetricKeyAlgorithm.Camellia128,
                        SymmetricKeyAlgorithm.Camellia192,
                        SymmetricKeyAlgorithm.Camellia256}

    @property
    def is_insecure(self) -> bool:
        insecure_ciphers = {SymmetricKeyAlgorithm.IDEA}
        return self in insecure_ciphers

    @property
    def block_size(self) -> int:
        if self in {SymmetricKeyAlgorithm.IDEA,
                    SymmetricKeyAlgorithm.TripleDES,
                    SymmetricKeyAlgorithm.CAST5,
                    SymmetricKeyAlgorithm.Blowfish}:
            return 64
        else:
            return 128

    @property
    def key_size(self) -> int:
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

    def gen_iv(self) -> bytes:
        return os.urandom(self.block_size // 8)

    def gen_key(self) -> bytes:
        return os.urandom(self.key_size // 8)


class PubKeyAlgorithm(IntEnum):
    """Supported public key algorithms."""
    Unknown = -1
    Invalid = 0x00
    #: Signifies that a key is an RSA key.
    RSAEncryptOrSign = 0x01
    RSAEncrypt = 0x02  # deprecated
    RSASign = 0x03     # deprecated
    #: Signifies that a key is an ElGamal key.
    ElGamal = 0x10
    #: Signifies that a key is a DSA key.
    DSA = 0x11
    #: Signifies that a key is an ECDH key.
    ECDH = 0x12
    #: Signifies that a key is an ECDSA key.
    ECDSA = 0x13
    FormerlyElGamalEncryptOrSign = 0x14  # deprecated - do not generate
    DiffieHellman = 0x15  # X9.42
    EdDSA = 0x16  # https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-04

    @classmethod
    def _missing_(cls, val: object) -> PubKeyAlgorithm:
        if not isinstance(val, int):
            raise TypeError(f"cannot look up PubKeyAlgorithm by non-int {type(val)}")
        return cls.Unknown

    @property
    def can_gen(self) -> bool:
        return self in {PubKeyAlgorithm.RSAEncryptOrSign,
                        PubKeyAlgorithm.DSA,
                        PubKeyAlgorithm.ECDSA,
                        PubKeyAlgorithm.ECDH,
                        PubKeyAlgorithm.EdDSA}

    @property
    def can_encrypt(self) -> bool:  # pragma: no cover
        return self in {PubKeyAlgorithm.RSAEncryptOrSign, PubKeyAlgorithm.ElGamal, PubKeyAlgorithm.ECDH}

    @property
    def can_sign(self) -> bool:
        return self in {PubKeyAlgorithm.RSAEncryptOrSign, PubKeyAlgorithm.DSA, PubKeyAlgorithm.ECDSA, PubKeyAlgorithm.EdDSA}

    @property
    def deprecated(self) -> bool:
        return self in {PubKeyAlgorithm.RSAEncrypt,
                        PubKeyAlgorithm.RSASign,
                        PubKeyAlgorithm.FormerlyElGamalEncryptOrSign}

    def validate_params(self, size) -> SecurityIssues:
        min_size = MINIMUM_ASYMMETRIC_KEY_LENGTHS.get(self)
        if min_size is not None:
            if isinstance(min_size, set):
                # ECC
                curve = size
                safe_curves = min_size
                if curve in safe_curves:
                    return SecurityIssues.OK
                else:
                    return SecurityIssues.InsecureCurve
            else:
                # not ECC
                if size >= min_size:
                    return SecurityIssues.OK
                else:
                    return SecurityIssues.AsymmetricKeyLengthIsTooShort
        # min_size is None
        return SecurityIssues.BrokenAsymmetricFunc


class S2KUsage(IntEnum):
    '''S2KUsage octet for secret key protection.'''
    Unprotected = 0

    # Legacy keys might be protected directly with a SymmetricKeyAlgorithm (this is a bad idea):
    IDEA = 1
    TripleDES = 2
    CAST5 = 3
    Blowfish = 4
    AES128 = 7
    AES192 = 8
    AES256 = 9
    Twofish256 = 10
    Camellia128 = 11
    Camellia192 = 12
    Camellia256 = 13

    # sensible use of tamper-resistant CFB:
    CFB = 254
    # legacy use of CFB:
    MalleableCFB = 255


class CompressionAlgorithm(IntEnum):
    """Supported compression algorithms."""
    #: No compression
    Uncompressed = 0x00
    #: ZIP DEFLATE
    ZIP = 0x01
    #: ZIP DEFLATE with zlib headers
    ZLIB = 0x02
    #: Bzip2
    BZ2 = 0x03

    def compress(self, data: bytes) -> bytes:
        if self is CompressionAlgorithm.Uncompressed:
            return data

        if self is CompressionAlgorithm.ZIP:
            return zlib.compress(data)[2:-4]

        if self is CompressionAlgorithm.ZLIB:
            return zlib.compress(data)

        if self is CompressionAlgorithm.BZ2:
            return bz2.compress(data)

        raise NotImplementedError(self)

    def decompress(self, data: bytes) -> bytes:
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
    """Supported hash algorithms."""
    Unknown = -1
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
    SHA3_256 = 12
    _reserved_5 = 13
    SHA3_512 = 14

    @classmethod
    def _missing_(cls, val: object) -> HashAlgorithm:
        if not isinstance(val, int):
            raise TypeError(f"cannot look up HashAlgorithm by non-int {type(val)}")
        return cls.Unknown

    @property
    def hasher(self) -> hashes.Hash:
        return hashes.Hash(getattr(hashes, self.name)())

    @property
    def digest_size(self) -> int:
        return getattr(hashes, self.name).digest_size

    @property
    def is_supported(self) -> bool:
        return True

    @property
    def is_second_preimage_resistant(self) -> bool:
        return self in {HashAlgorithm.SHA1}

    @property
    def is_collision_resistant(self) -> bool:
        return self in {HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512,
                        HashAlgorithm.SHA3_256, HashAlgorithm.SHA512}

    @property
    def is_considered_secure(self) -> SecurityIssues:
        if self.is_collision_resistant:
            return SecurityIssues.OK

        warnings.warn('Hash function {hash} is not considered collision resistant'.format(hash=repr(self)))
        issues = SecurityIssues.HashFunctionNotCollisionResistant

        if not self.is_second_preimage_resistant:
            issues |= SecurityIssues.HashFunctionNotSecondPreimageResistant

        return issues

    def digest(self, data: bytes) -> bytes:
        'shortcut for computing a quick one-off digest'
        ctx = hashes.Hash(getattr(hashes, self.name)())
        ctx.update(data)
        return ctx.finalize()


class ECFields(NamedTuple):
    name: str
    OID: str
    OID_der: bytes
    key_size: int  # in bits
    kdf_halg: HashAlgorithm
    kek_alg: SymmetricKeyAlgorithm
    curve: Type

    def __repr__(self) -> str:
        return f'<Elliptic Curve {self.name} ({self.OID})>'


class EllipticCurveOID(Enum):
    """Supported elliptic curves."""

    #: DJB's fast elliptic curve
    Curve25519 = (x25519, '1.3.6.1.4.1.3029.1.5.1',
                  b'\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01',
                  'X25519', 256)
    #: Twisted Edwards variant of Curve25519
    Ed25519 = (ed25519, '1.3.6.1.4.1.11591.15.1',
               b'\x2b\x06\x01\x04\x01\xda\x47\x0f\x01',
               'Ed25519', 256)
    #: NIST P-256, also known as SECG curve secp256r1
    NIST_P256 = (ec.SECP256R1, '1.2.840.10045.3.1.7',
                 b'\x2a\x86\x48\xce\x3d\x03\x01\x07')
    #: NIST P-384, also known as SECG curve secp384r1
    NIST_P384 = (ec.SECP384R1, '1.3.132.0.34',
                 b'\x2b\x81\x04\x00\x22')
    #: NIST P-521, also known as SECG curve secp521r1
    NIST_P521 = (ec.SECP521R1, '1.3.132.0.35',
                 b'\x2b\x81\x04\x00\x23')
    #: Brainpool Standard Curve, 256-bit
    Brainpool_P256 = (ec.BrainpoolP256R1, '1.3.36.3.3.2.8.1.1.7',
                      b'\x2b\x24\x03\x03\x02\x08\x01\x01\x07')
    #: Brainpool Standard Curve, 384-bit
    Brainpool_P384 = (ec.BrainpoolP384R1, '1.3.36.3.3.2.8.1.1.11',
                      b'\x2b\x24\x03\x03\x02\x08\x01\x01\x0b')
    #: Brainpool Standard Curve, 512-bit
    Brainpool_P512 = (ec.BrainpoolP512R1, '1.3.36.3.3.2.8.1.1.13',
                      b'\x2b\x24\x03\x03\x02\x08\x01\x01\x0d')
    #: SECG curve secp256k1
    SECP256K1 = (ec.SECP256K1, '1.3.132.0.10',
                 b'\x2b\x81\x04\x00\x0a')

    def __new__(cls, impl_cls: Type, oid: str, oid_der: bytes, name: Optional[str] = None, key_size_bits: Optional[int] = None) -> EllipticCurveOID:
        # preprocessing stage for enum members:
        #  - set enum_member.value to ObjectIdentifier(oid)
        #  - if curve is not None and curve.name is in ec._CURVE_TYPES, set enum_member.curve to curve
        #  - otherwise, set enum_member.curve to None
        obj = object.__new__(cls)
        if name is None:
            newname = impl_cls.name
            if not isinstance(newname, str):
                raise TypeError(f"{impl_cls}.name is not string!")
            name = newname
        if key_size_bits is None:
            newks = impl_cls.key_size
            if not isinstance(newks, int):
                raise TypeError(f"{impl_cls}.name is not string!")
            key_size_bits = newks

        algs = {256: (HashAlgorithm.SHA256, SymmetricKeyAlgorithm.AES128),
                384: (HashAlgorithm.SHA384, SymmetricKeyAlgorithm.AES192),
                512: (HashAlgorithm.SHA512, SymmetricKeyAlgorithm.AES256),
                521: (HashAlgorithm.SHA512, SymmetricKeyAlgorithm.AES256)}

        (kdf_alg, kek_alg) = algs[key_size_bits]

        obj._value_ = ECFields(name, oid, oid_der, key_size_bits, kdf_alg, kek_alg, impl_cls)

        return obj

    @classmethod
    def from_key_size(cls, key_size: int) -> Optional["EllipticCurveOID"]:
        for c in EllipticCurveOID:
            if c.value.key_size == key_size:
                return c
        warnings.warn(f"Cannot find any Elliptic curve of size: {key_size}")
        return None

    @classmethod
    def from_OID(cls, oid: bytes) -> Union["EllipticCurveOID", bytes]:
        for c in EllipticCurveOID:
            if c.value.OID_der == oid:
                return c
        warnings.warn(f"Unknown Elliptic curve OID: {oid!r}")
        return oid

    @classmethod
    def parse(cls, packet: bytearray) -> Union["EllipticCurveOID", bytes]:
        oidlen = packet[0]
        del packet[0]
        ret = EllipticCurveOID.from_OID(bytes(packet[:oidlen]))
        del packet[:oidlen]
        return ret

    @property
    def key_size(self) -> int:
        return self.value.key_size

    @property
    def oid(self) -> str:
        return self.value.OID

    @property
    def kdf_halg(self) -> HashAlgorithm:
        return self.value.kdf_halg

    @property
    def kek_alg(self) -> SymmetricKeyAlgorithm:
        return self.value.kek_alg

    @property
    def curve(self) -> Type:
        return self.value.curve

    @property
    def can_gen(self) -> bool:
        return True

    def __bytes__(self) -> bytes:
        return bytes([len(self.value.OID_der)]) + self.value.OID_der

    def __len__(self) -> int:
        return len(self.value.OID_der) + 1


class RevocationReason(IntEnum):
    """Reasons explaining why a key or certificate was revoked."""
    #: No reason was specified. This is the default reason.
    NotSpecified = 0x00
    #: The key was superseded by a new key. Only meaningful when revoking a key.
    Superseded = 0x01
    #: Key material has been compromised. Only meaningful when revoking a key.
    Compromised = 0x02
    #: Key is retired and no longer used. Only meaningful when revoking a key.
    Retired = 0x03
    #: User ID information is no longer valid. Only meaningful when revoking a certification of a user id.
    UserID = 0x20


class SigSubpacketType(IntEnum):
    CreationTime = 2
    SigExpirationTime = 3
    ExportableCertification = 4
    TrustSignature = 5
    RegularExpression = 6
    Revocable = 7
    KeyExpirationTime = 9
    PreferredSymmetricAlgorithms = 11
    RevocationKey = 12
    IssuerKeyID = 16
    NotationData = 20
    PreferredHashAlgorithms = 21
    PreferredCompressionAlgorithms = 22
    KeyServerPreferences = 23
    PreferredKeyServer = 24
    PrimaryUserID = 25
    PolicyURI = 26
    KeyFlags = 27
    SignersUserID = 28
    ReasonForRevocation = 29
    Features = 30
    SignatureTarget = 31
    EmbeddedSignature = 32
    IssuerFingerprint = 33
    IntendedRecipientFingerprint = 35
    AttestedCertifications = 37


class AttributeType(IntEnum):
    Image = 1


class ImageEncoding(IntEnum):
    Unknown = -1
    Invalid = 0x00
    JPEG = 0x01

    @classmethod
    def encodingof(cls, imagebytes: bytes) -> ImageEncoding:
        if imagebytes[6:10] in (b'JFIF', b'Exif') or imagebytes[:4] == b'\xff\xd8\xff\xdb':
            return ImageEncoding.JPEG
        return ImageEncoding.Unknown  # pragma: no cover

    @classmethod
    def _missing_(cls, val: object) -> ImageEncoding:
        if not isinstance(val, int):
            raise TypeError(f"cannot look up ImageEncoding by non-int {type(val)}")
        return cls.Unknown


class SignatureType(IntEnum):
    """Types of signatures that can be found in a Signature packet."""

    #: The signer either owns this document, created it, or certifies that it
    #: has not been modified.
    BinaryDocument = 0x00

    #: The signer either owns this document, created it, or certifies that it
    #: has not been modified.  The signature is calculated over the text
    #: data with its line endings converted to ``<CR><LF>``.
    CanonicalDocument = 0x01

    #: This signature is a signature of only its own subpacket contents.
    #: It is calculated identically to a signature over a zero-length
    #: ``BinaryDocument``.
    Standalone = 0x02

    #: The issuer of this certification does not make any particular
    #: claim as to how well the certifier has checked that the owner
    #: of the key is in fact the person described by the User ID.
    Generic_Cert = 0x10

    #: The issuer of this certification has not done any verification of
    #: the claim that the owner of this key is the User ID specified.
    Persona_Cert = 0x11

    #: The issuer of this certification has done some casual
    #: verification of the claim of identity.
    Casual_Cert = 0x12

    #: The issuer of this certification has done substantial
    #: verification of the claim of identity.
    Positive_Cert = 0x13

    #: This signature is issued by the primary key over itself and its user ID (or user attribute).
    #: See `draft-ietf-openpgp-rfc4880bis-08 <https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08#section-5.2.1>`_
    Attestation = 0x16

    #: This signature is a statement by the top-level signing key that
    #: indicates that it owns the subkey.  This signature is calculated
    #: directly on the primary key and subkey, and not on any User ID or
    #: other packets.
    Subkey_Binding = 0x18

    #: This signature is a statement by a signing subkey, indicating
    #: that it is owned by the primary key and subkey. This signature
    #: is calculated the same way as a ``Subkey_Binding`` signature.
    PrimaryKey_Binding = 0x19

    #: A signature calculated directly on a key.  It binds the
    #: information in the Signature subpackets to the key, and is
    #: appropriate to be used for subpackets that provide information
    #: about the key, such as the Revocation Key subpacket.  It is also
    #: appropriate for statements that non-self certifiers want to make
    #: about the key itself, rather than the binding between a key and a
    #: name.
    DirectlyOnKey = 0x1F

    #: A signature calculated directly on the key being revoked.
    #: Only revocation signatures by the key being revoked, or by an
    #: authorized revocation key, should be considered valid revocation signatures.
    KeyRevocation = 0x20

    #: A signature calculated directly on the subkey being revoked.
    #: Only revocation signatures by the top-level signature key that is bound to this subkey,
    #: or by an authorized revocation key, should be considered valid revocation signatures.
    SubkeyRevocation = 0x28

    #: This signature revokes an earlier User ID certification signature or direct-key signature.
    #: It should be issued by the same key that issued the revoked signature or an authorized revocation key.
    #: The signature is computed over the same data as the certificate that it revokes.
    CertRevocation = 0x30

    #: This signature is only meaningful for the timestamp contained in it.
    Timestamp = 0x40

    #: This signature is a signature over some other OpenPGP Signature
    #: packet(s).  It is analogous to a notary seal on the signed data.
    ThirdParty_Confirmation = 0x50


class KeyServerPreferences(IntFlag):
    NoModify = 0x80


class String2KeyType(IntEnum):
    Unknown = -1
    Simple = 0
    Salted = 1
    Reserved = 2
    Iterated = 3
    Argon2 = 4
    GNUExtension = 101

    @classmethod
    def _missing_(cls, val: object) -> String2KeyType:
        if not isinstance(val, int):
            raise TypeError(f"cannot look up String2KeyType by non-int {type(val)}")
        return cls.Unknown

    @property
    def salt_length(self) -> int:
        ks = {String2KeyType.Salted: 8,
              String2KeyType.Iterated: 8,
              String2KeyType.Argon2: 16,
              }
        return ks.get(self, 0)

    @property
    def has_iv(self) -> bool:
        'When this S2K type is used for secret key protection, should we expect an IV to follow?'
        return self in [String2KeyType.Simple,
                        String2KeyType.Salted,
                        String2KeyType.Iterated,
                        ]


class S2KGNUExtension(IntEnum):
    NoSecret = 1
    Smartcard = 2


class TrustLevel(IntEnum):
    Unknown = 0
    Expired = 1
    Undefined = 2
    Never = 3
    Marginal = 4
    Fully = 5
    Ultimate = 6


class KeyFlags(IntFlag):
    """Flags that determine a key's capabilities."""
    #: Signifies that a key may be used to certify keys and user ids. Primary keys always have this, even if it is not specified.
    Certify = 0x01
    #: Signifies that a key may be used to sign messages and documents.
    Sign = 0x02
    #: Signifies that a key may be used to encrypt messages.
    EncryptCommunications = 0x04
    #: Signifies that a key may be used to encrypt storage. Currently equivalent to :py:obj:`~pgpy.constants.EncryptCommunications`.
    EncryptStorage = 0x08
    #: Signifies that the private component of a given key may have been split by a secret-sharing mechanism. Split
    #: keys are not currently supported by PGPy.
    Split = 0x10
    #: Signifies that a key may be used for authentication.
    Authentication = 0x20
    #: Signifies that the private component of a key may be in the possession of more than one person.
    MultiPerson = 0x80


class Features(IntFlag):
    SEIPDv1 = 0x01
    # alias (the old name, in RFC 4880):
    ModificationDetection = 0x01
    UnknownFeature02 = 0x02
    UnknownFeature04 = 0x04
    UnknownFeature08 = 0x08
    UnknownFeature10 = 0x10
    UnknownFeature20 = 0x20
    UnknownFeature40 = 0x40
    UnknownFeature80 = 0x80

    @classproperty
    def pgpy_features(cls) -> Features:
        return Features.SEIPDv1


class RevocationKeyClass(IntFlag):
    Sensitive = 0x40
    Normal = 0x80


class NotationDataFlags(IntFlag):
    HumanReadable = 0x80


class TrustFlags(IntFlag):
    Revoked = 0x20
    SubRevoked = 0x40
    Disabled = 0x80
    PendingCheck = 0x100


class SecurityIssues(IntFlag):
    OK = 0
    WrongSig = (1 << 0)
    Expired = (1 << 1)
    Disabled = (1 << 2)
    Revoked = (1 << 3)
    Invalid = (1 << 4)
    BrokenAsymmetricFunc = (1 << 5)
    HashFunctionNotCollisionResistant = (1 << 6)
    HashFunctionNotSecondPreimageResistant = (1 << 7)
    AsymmetricKeyLengthIsTooShort = (1 << 8)
    InsecureCurve = (1 << 9)
    NoSelfSignature = (1 << 10)
    AlgorithmUnknown = (1 << 11)

    @property
    def causes_signature_verify_to_fail(self) -> bool:
        return self in {
            SecurityIssues.WrongSig,
            SecurityIssues.Expired,
            SecurityIssues.Disabled,
            SecurityIssues.Invalid,
            SecurityIssues.NoSelfSignature,
            SecurityIssues.AlgorithmUnknown,
        }


# https://safecurves.cr.yp.to/
SAFE_CURVES = {
    EllipticCurveOID.Curve25519,
    EllipticCurveOID.Ed25519,
}

MINIMUM_ASYMMETRIC_KEY_LENGTHS = {
    PubKeyAlgorithm.RSAEncryptOrSign: 2048,
    PubKeyAlgorithm.RSASign: 2048,
    PubKeyAlgorithm.ElGamal: 2048,
    PubKeyAlgorithm.DSA: 2048,
    ##
    PubKeyAlgorithm.ECDSA: SAFE_CURVES,
    PubKeyAlgorithm.EdDSA: SAFE_CURVES,
    PubKeyAlgorithm.ECDH: SAFE_CURVES,
}
