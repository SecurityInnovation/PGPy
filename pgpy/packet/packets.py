""" packet.py
"""
from __future__ import annotations

import abc
import binascii
import calendar
import copy
import os
import warnings

from datetime import datetime, timezone

from math import log2

from typing import ByteString, Optional, Tuple, Union

from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

from ..symenc import AEAD

from .fields import DSAPriv, DSAPub, DSASignature
from .fields import ECDSAPub, ECDSAPriv, ECDSASignature
from .fields import ECDHPub, ECDHPriv, ECDHCipherText
from .fields import EdDSAPub, EdDSAPriv, EdDSASignature
from .fields import ElGCipherText, ElGPriv, ElGPub
from .fields import CipherText
from .fields import Signature as SignatureField
from .fields import PubKey as PubKeyField
from .fields import PrivKey as PrivKeyField
from .fields import OpaquePubKey
from .fields import OpaquePrivKey
from .fields import OpaqueSignature
from .fields import RSACipherText, RSAPriv, RSAPub, RSASignature
from .fields import String2Key
from .fields import S2KSpecifier
from .fields import SubPackets
from .fields import UserAttributeSubPackets

from .types import Packet
from .types import Primary
from .types import Private
from .types import Public
from .types import Sub
from .types import VersionedPacket
from .types import VersionedHeader

from ..constants import PacketType
from ..constants import CompressionAlgorithm
from ..constants import HashAlgorithm
from ..constants import PubKeyAlgorithm
from ..constants import SignatureType
from ..constants import SymmetricKeyAlgorithm
from ..constants import TrustFlags
from ..constants import TrustLevel
from ..constants import AEADMode

from ..decorators import sdproperty

from ..errors import PGPDecryptionError
from ..errors import PGPEncryptionError

from ..symenc import _cfb_decrypt
from ..symenc import _cfb_encrypt
from ..symenc import AEAD

from ..types import Fingerprint
from ..types import KeyID

__all__ = ['PKESessionKey',
           'PKESessionKeyV3',
           'PKESessionKeyV6',
           'Signature',
           'SignatureV4',
           'SKESessionKey',
           'SKESessionKeyV4',
           'SKESessionKeyV6',
           'OnePassSignature',
           'OnePassSignatureV3',
           'PrivKey',
           'PubKey',
           'PubKeyV4',
           'PrivKeyV4',
           'PrivSubKey',
           'PrivSubKeyV4',
           'CompressedData',
           'SKEData',
           'Marker',
           'Padding',
           'LiteralData',
           'Trust',
           'UserID',
           'PubSubKey',
           'PubSubKeyV4',
           'UserAttribute',
           'IntegrityProtectedSKEData',
           'IntegrityProtectedSKEDataV1',
           'IntegrityProtectedSKEDataV2',
           'MDC']


class PKESessionKey(VersionedPacket):
    __typeid__ = PacketType.PublicKeyEncryptedSessionKey
    __ver__ = 0

    def __init__(self) -> None:
        super().__init__()
        self._pkalg: PubKeyAlgorithm = PubKeyAlgorithm.Unknown
        self._opaque_pkalg: int = 0
        self.ct: Optional[CipherText] = None

    @abc.abstractmethod
    def decrypt_sk(self, pk: PrivKey) -> Tuple[Optional[SymmetricKeyAlgorithm], bytes]:
        raise NotImplementedError()

    @abc.abstractmethod
    def encrypt_sk(self, pk: PubKey, symalg: Optional[SymmetricKeyAlgorithm], symkey: bytes) -> None:
        raise NotImplementedError()

    # a PKESK should return a pointer to the recipient, or None
    @abc.abstractproperty
    def encrypter(self) -> Optional[Union[KeyID, Fingerprint]]:
        raise NotImplementedError()

    @sdproperty
    def pkalg(self):
        return self._pkalg

    @pkalg.register
    def pkalg_int(self, val: int) -> None:
        if isinstance(val, PubKeyAlgorithm):
            self._pkalg = val
        else:
            self._pkalg = PubKeyAlgorithm(val)
            if self._pkalg is PubKeyAlgorithm.Invalid:
                self._opaque_pkalg = val

        if self._pkalg in {PubKeyAlgorithm.RSAEncryptOrSign, PubKeyAlgorithm.RSAEncrypt}:
            self.ct = RSACipherText()
        elif self._pkalg in {PubKeyAlgorithm.ElGamal, PubKeyAlgorithm.FormerlyElGamalEncryptOrSign}:
            self.ct = ElGCipherText()
        elif self._pkalg is PubKeyAlgorithm.ECDH:
            self.ct = ECDHCipherText()


class PKESessionKeyV3(PKESessionKey):
    """
    5.1.  Public-Key Encrypted Session Key Packets (Tag 1)

    A Public-Key Encrypted Session Key packet holds the session key used
    to encrypt a message.  Zero or more Public-Key Encrypted Session Key
    packets and/or Symmetric-Key Encrypted Session Key packets may
    precede a Symmetrically Encrypted Data Packet, which holds an
    encrypted message.  The message is encrypted with the session key,
    and the session key is itself encrypted and stored in the Encrypted
    Session Key packet(s).  The Symmetrically Encrypted Data Packet is
    preceded by one Public-Key Encrypted Session Key packet for each
    OpenPGP key to which the message is encrypted.  The recipient of the
    message finds a session key that is encrypted to their public key,
    decrypts the session key, and then uses the session key to decrypt
    the message.

    The body of this packet consists of:

     - A one-octet number giving the version number of the packet type.
       The currently defined value for packet version is 3.

     - An eight-octet number that gives the Key ID of the public key to
       which the session key is encrypted.  If the session key is
       encrypted to a subkey, then the Key ID of this subkey is used
       here instead of the Key ID of the primary key.

     - A one-octet number giving the public-key algorithm used.

     - A string of octets that is the encrypted session key.  This
       string takes up the remainder of the packet, and its contents are
       dependent on the public-key algorithm used.

    Algorithm Specific Fields for RSA encryption

     - multiprecision integer (MPI) of RSA encrypted value m**e mod n.

    Algorithm Specific Fields for Elgamal encryption:

     - MPI of Elgamal (Diffie-Hellman) value g**k mod p.

     - MPI of Elgamal (Diffie-Hellman) value m * y**k mod p.

    The value "m" in the above formulas is derived from the session key
    as follows.  First, the session key is prefixed with a one-octet
    algorithm identifier that specifies the symmetric encryption
    algorithm used to encrypt the following Symmetrically Encrypted Data
    Packet.  Then a two-octet checksum is appended, which is equal to the
    sum of the preceding session key octets, not including the algorithm
    identifier, modulo 65536.  This value is then encoded as described in
    PKCS#1 block encoding EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to
    form the "m" value used in the formulas above.  See Section 13.1 of
    this document for notes on OpenPGP's use of PKCS#1.

    Note that when an implementation forms several PKESKs with one
    session key, forming a message that can be decrypted by several keys,
    the implementation MUST make a new PKCS#1 encoding for each key.

    An implementation MAY accept or use a Key ID of zero as a "wild card"
    or "speculative" Key ID.  In this case, the receiving implementation
    would try all available private keys, checking for a valid decrypted
    session key.  This format helps reduce traffic analysis of messages.
    """
    __ver__ = 3

    @sdproperty
    def encrypter(self) -> Optional[KeyID]:
        return self._encrypter

    @encrypter.register
    def encrypter_bin(self, val: Union[bytearray, KeyID]) -> None:
        if isinstance(val, KeyID):
            self._encrypter: Optional[KeyID]
        elif val == b'\x00' * 8:
            self._encrypter = None
        else:
            self._encrypter = KeyID(val)

    def __init__(self) -> None:
        super().__init__()
        self._encrypter = None

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        if self._encrypter is None:
            _bytes += b'\x00' * 8
        else:
            _bytes += bytes(self._encrypter)
        if self.pkalg == PubKeyAlgorithm.Invalid:
            _bytes.append(self._opaque_pkalg)
        else:
            _bytes.append(self.pkalg)
        _bytes += self.ct.__bytearray__() if self.ct is not None else b'\x00' * (self.header.length - 10)
        return _bytes

    def __copy__(self):
        sk = self.__class__()
        sk.header = copy.copy(self.header)
        sk._encrypter = self._encrypter
        sk.pkalg = self.pkalg
        if self.pkalg == PubKeyAlgorithm.Invalid:
            sk._opaque_pkalg = self._opaque_pkalg
        if self.ct is not None:
            sk.ct = copy.copy(self.ct)

        return sk

    def decrypt_sk(self, pk: PrivKey) -> Tuple[Optional[SymmetricKeyAlgorithm], bytes]:
        if not isinstance(pk.keymaterial, PrivKeyField):
            raise TypeError(f"PKESKv3.decrypt_sk() expected private key material, got {type(pk.keymaterial)}")
        if self.ct is None:
            raise TypeError("PKESKv3.decrypt_sk() expected ciphertext, got None")

        return pk.keymaterial.decrypt(self.ct, pk.fingerprint, True)

    def encrypt_sk(self, pk: PubKey, symalg: Optional[SymmetricKeyAlgorithm], symkey: bytes) -> None:
        if symalg is None:
            raise ValueError('PKESKv3: must pass a symmetric key algorithm explicitly when encrypting')
        if pk.keymaterial is None:
            raise ValueError('PKESKv3: public key material must be instantiated')

        self.ct = pk.keymaterial.encrypt(symalg, symkey, pk.fingerprint)

        self.update_hlen()

    def parse(self, packet):
        super().parse(packet)
        self.encrypter = packet[:8]
        del packet[:8]

        self.pkalg = packet[0]
        del packet[0]

        if self.ct is not None:
            self.ct.parse(packet)

        else:  # pragma: no cover
            del packet[:(self.header.length - 10)]


class PKESessionKeyV6(PKESessionKey):
    __ver__ = 6

    def __init__(self) -> None:
        super().__init__()
        self._encrypter: Optional[Fingerprint] = None

    @sdproperty
    def encrypter(self) -> Optional[Fingerprint]:
        return self._encrypter

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        if self._encrypter is None:
            _bytes.append(0)
        else:
            _bytes.append(len(bytes(self._encrypter)) + 1)
            _bytes.append(self._encrypter.version)
            _bytes += bytes(self._encrypter)
        _bytes.append(self.pkalg)
        _bytes += self.ct.__bytearray__() if self.ct is not None else b'\x00' * (self.header.length - 10)
        return _bytes

    def __copy__(self) -> PKESessionKeyV6:
        sk = self.__class__()
        sk.header = copy.copy(self.header)
        sk._encrypter = self._encrypter
        sk.pkalg = self.pkalg
        if self.ct is not None:
            sk.ct = copy.copy(self.ct)
        return sk

    def decrypt_sk(self, pk: PrivKey) -> Tuple[Optional[SymmetricKeyAlgorithm], bytes]:
        algo: Optional[SymmetricKeyAlgorithm]
        symkey: bytes
        if self.ct is None:
            raise PGPDecryptionError("PKESKv6: Tried to decrypt session key when ciphertext was not initialized")
        return pk.keymaterial.decrypt(self.ct, pk.fingerprint, False)

    def encrypt_sk(self, pk: PubKey, symalg: Optional[SymmetricKeyAlgorithm], symkey: bytes, **kwargs) -> None:
        if symalg is not None:
            raise ValueError(f"PKESKv6 does not encrypt the symmetric key algorithm, but {symalg} was supplied (should be None)")
        self._encrypter = pk.fingerprint
        self.pkalg = pk.pkalg
        if self.ct is None:
            raise PGPEncryptionError(f"Don't know how to encrypt to {pk.pkalg!r}")
        self.ct = pk.keymaterial.encrypt(None, symkey, pk.fingerprint)
        self.update_hlen()

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)
        fplen = packet[0]
        del packet[0]

        if fplen:
            # the key version
            fpversion = packet[0]
            del packet[0]

            Fingerprint.confirm_expected_length(fpversion, fplen - 1)
            # extract the fingerprint
            self._encrypter = Fingerprint(bytes(packet[:fplen - 1]), version=fpversion)
            del packet[:fplen - 1]

        self.pkalg = packet[0]
        del packet[0]

        if self.ct is not None:
            self.ct.parse(packet)
        else:  # pragma: no cover
            del packet[:(self.header.length - (2 + fplen + 1))]


class Signature(VersionedPacket):
    __typeid__ = PacketType.Signature
    __ver__ = 0
    __subpacket_width__ = 2

    def __init__(self) -> None:
        super().__init__()
        self._sigtype: Optional[SignatureType] = None
        self._pubalg: Optional[PubKeyAlgorithm] = None
        self._halg: Optional[HashAlgorithm] = None
        self.subpackets = SubPackets(self.__subpacket_width__)
        self.hash2 = bytearray(2)
        self._signature: SignatureField = OpaqueSignature()

    @sdproperty
    def sigtype(self) -> Optional[SignatureType]:
        return self._sigtype

    @sigtype.register
    def sigtype_int(self, val: int) -> None:
        self._sigtype = SignatureType(val)

    @sdproperty
    def pubalg(self) -> Optional[PubKeyAlgorithm]:
        return self._pubalg

    @pubalg.register
    def pubalg_int(self, val: int) -> None:
        if isinstance(val, PubKeyAlgorithm):
            self._pubalg = val
        else:
            self._pubalg = PubKeyAlgorithm(val)
            if self._pubalg is PubKeyAlgorithm.Unknown:
                self._opaque_pubalg: int = val

        if self.pubalg in {PubKeyAlgorithm.RSAEncryptOrSign, PubKeyAlgorithm.RSASign}:
            self.signature = RSASignature()
        elif self.pubalg is PubKeyAlgorithm.DSA:
            self.signature = DSASignature()
        elif self.pubalg is PubKeyAlgorithm.ECDSA:
            self.signature = ECDSASignature()
        elif self.pubalg is PubKeyAlgorithm.EdDSA:
            self.signature = EdDSASignature()
        else:
            self.signature = OpaqueSignature()

    @sdproperty
    def halg(self) -> Optional[HashAlgorithm]:
        return self._halg

    @halg.register
    def halg_int(self, val: int) -> None:
        if isinstance(val, HashAlgorithm):
            self._halg = val
        else:
            self._halg = HashAlgorithm(val)
            if self._halg is HashAlgorithm.Unknown:
                self._opaque_halg = val

    @property
    def signature(self) -> SignatureField:
        return self._signature

    @signature.setter
    def signature(self, val: SignatureField) -> None:
        self._signature = val

    def update_hlen(self):
        self.subpackets.update_hlen()
        super().update_hlen()

    @abc.abstractmethod
    def make_onepass(self) -> OnePassSignature:
        raise NotImplementedError()

    @abc.abstractproperty
    def signer(self) -> Optional[Union[KeyID, Fingerprint]]:
        ...

    @abc.abstractmethod
    def canonical_bytes(self) -> bytearray:
        ...


class SignatureV4(Signature):
    """
    5.2.3.  Version 4 Signature Packet Format

    The body of a version 4 Signature packet contains:

     - One-octet version number (4).

     - One-octet signature type.

     - One-octet public-key algorithm.

     - One-octet hash algorithm.

     - Two-octet scalar octet count for following hashed subpacket data.
       Note that this is the length in octets of all of the hashed
       subpackets; a pointer incremented by this number will skip over
       the hashed subpackets.

     - Hashed subpacket data set (zero or more subpackets).

     - Two-octet scalar octet count for the following unhashed subpacket
       data.  Note that this is the length in octets of all of the
       unhashed subpackets; a pointer incremented by this number will
       skip over the unhashed subpackets.

     - Unhashed subpacket data set (zero or more subpackets).

     - Two-octet field holding the left 16 bits of the signed hash
       value.

     - One or more multiprecision integers comprising the signature.
       This portion is algorithm specific, as described above.

    The concatenation of the data being signed and the signature data
    from the version number through the hashed subpacket data (inclusive)
    is hashed.  The resulting hash value is what is signed.  The left 16
    bits of the hash are included in the Signature packet to provide a
    quick test to reject some invalid signatures.

    There are two fields consisting of Signature subpackets.  The first
    field is hashed with the rest of the signature data, while the second
    is unhashed.  The second set of subpackets is not cryptographically
    protected by the signature and should include only advisory
    information.

    The algorithms for converting the hash function result to a signature
    are described in a section below.
    """
    __ver__ = 4

    @property
    def signer(self) -> Optional[Union[KeyID, Fingerprint]]:
        if 'IssuerFingerprint' in self.subpackets:
            return self.subpackets['IssuerFingerprint'][-1].issuer_fingerprint
        elif 'Issuer' in self.subpackets:
            return self.subpackets['Issuer'][-1].issuer
        return None

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        _bytes += self.int_to_bytes(self.sigtype)
        if self.pubalg is PubKeyAlgorithm.Unknown:
            _bytes.append(self._opaque_pubalg)
        else:
            _bytes.append(self.pubalg)
        if self.halg is HashAlgorithm.Unknown:
            _bytes.append(self._opaque_halg)
        else:
            _bytes.append(self.halg)
        _bytes += self.subpackets.__bytearray__()
        _bytes += self.hash2
        _bytes += self.signature.__bytearray__()

        return _bytes

    def canonical_bytes(self) -> bytearray:
        '''Returns a bytearray that is the way the signature packet
        should be represented if it is itself being signed.

        from RFC 4880 section 5.2.4:

        When a signature is made over a Signature packet (type 0x50), the
        hash data starts with the octet 0x88, followed by the four-octet
        length of the signature, and then the body of the Signature packet.
        (Note that this is an old-style packet header for a Signature packet
        with the length-of-length set to zero.)  The unhashed subpacket data
        of the Signature packet being hashed is not included in the hash, and
        the unhashed subpacket data length value is set to zero.
        '''
        _body = bytearray()
        if not isinstance(self.header, VersionedHeader):
            raise TypeError(f"SignatureV4 should have VersionedHeader, had {type(self.header)}")
        _body += self.int_to_bytes(self.header.version)
        _body += self.int_to_bytes(self.sigtype)
        if self.pubalg is PubKeyAlgorithm.Unknown:
            _body.append(self._opaque_pubalg)
        else:
            _body.append(self.pubalg)
        if self.halg is HashAlgorithm.Unknown:
            _body.append(self._opaque_halg)
        else:
            _body.append(self.halg)
        _body += self.subpackets.__hashbytearray__()
        _body += self.int_to_bytes(0, minlen=2)  # empty unhashed subpackets
        _body += self.hash2
        _body += self.signature.__bytearray__()

        _hdr = bytearray()
        _hdr += b'\x88'
        _hdr += self.int_to_bytes(len(_body), minlen=4)
        return _hdr + _body

    def __copy__(self) -> SignatureV4:
        spkt = SignatureV4()
        spkt.header = copy.copy(self.header)
        spkt._sigtype = self._sigtype
        spkt._pubalg = self._pubalg
        if self._pubalg is PubKeyAlgorithm.Unknown:
            spkt._opaque_pubalg = self._opaque_pubalg
        spkt._halg = self._halg
        if self._halg is HashAlgorithm.Unknown:
            spkt._opaque_halg = self._opaque_halg

        spkt.subpackets = copy.copy(self.subpackets)
        spkt.hash2 = copy.copy(self.hash2)
        spkt.signature = copy.copy(self.signature)

        return spkt

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)
        self.sigtype = packet[0]
        del packet[0]

        self.pubalg = packet[0]
        del packet[0]

        self.halg = packet[0]
        del packet[0]

        self.subpackets.parse(packet)

        self.hash2 = packet[:2]
        del packet[:2]

        self.signature.parse(packet)

    def make_onepass(self) -> OnePassSignatureV3:
        signer = self.signer
        if signer is None:
            raise ValueError("Cannot make a one-pass signature without knowledge of who the signer is")
        if isinstance(signer, Fingerprint):
            signer = signer.keyid

        onepass = OnePassSignatureV3()
        onepass.sigtype = self.sigtype
        onepass.halg = self.halg
        onepass.pubalg = self.pubalg

        onepass._signer = signer
        onepass.update_hlen()
        return onepass


class SKESessionKey(VersionedPacket):
    __typeid__ = PacketType.SymmetricKeyEncryptedSessionKey
    __ver__ = 0

    def __init__(self) -> None:
        super().__init__()
        self.symalg = SymmetricKeyAlgorithm.AES256
        self.s2kspec = S2KSpecifier()

    # FIXME: the type signature for this function is awkward because
    # the symmetric algorithm used by the following SEIPDv2 packet is
    # not encoded in the SKESKv6:
    @abc.abstractmethod
    def decrypt_sk(self, passphrase: Union[str, bytes]) -> Tuple[Optional[SymmetricKeyAlgorithm], bytes]:
        raise NotImplementedError()

    @abc.abstractmethod
    def encrypt_sk(self, passphrase: Union[str, bytes], sk: ByteString):
        raise NotImplementedError()


class SKESessionKeyV4(SKESessionKey):
    """
    5.3.  Symmetric-Key Encrypted Session Key Packets (Tag 3)

    The Symmetric-Key Encrypted Session Key packet holds the
    symmetric-key encryption of a session key used to encrypt a message.
    Zero or more Public-Key Encrypted Session Key packets and/or
    Symmetric-Key Encrypted Session Key packets may precede a
    Symmetrically Encrypted Data packet that holds an encrypted message.
    The message is encrypted with a session key, and the session key is
    itself encrypted and stored in the Encrypted Session Key packet or
    the Symmetric-Key Encrypted Session Key packet.

    If the Symmetrically Encrypted Data packet is preceded by one or
    more Symmetric-Key Encrypted Session Key packets, each specifies a
    passphrase that may be used to decrypt the message.  This allows a
    message to be encrypted to a number of public keys, and also to one
    or more passphrases.  This packet type is new and is not generated
    by PGP 2.x or PGP 5.0.

    The body of this packet consists of:

     - A one-octet version number.  The only currently defined version
       is 4.

     - A one-octet number describing the symmetric algorithm used.

     - A string-to-key (S2K) specifier, length as defined above.

     - Optionally, the encrypted session key itself, which is decrypted
       with the string-to-key object.

    If the encrypted session key is not present (which can be detected
    on the basis of packet length and S2K specifier size), then the S2K
    algorithm applied to the passphrase produces the session key for
    decrypting the file, using the symmetric cipher algorithm from the
    Symmetric-Key Encrypted Session Key packet.

    If the encrypted session key is present, the result of applying the
    S2K algorithm to the passphrase is used to decrypt just that
    encrypted session key field, using CFB mode with an IV of all zeros.
    The decryption result consists of a one-octet algorithm identifier
    that specifies the symmetric-key encryption algorithm used to
    encrypt the following Symmetrically Encrypted Data packet, followed
    by the session key octets themselves.

    Note: because an all-zero IV is used for this decryption, the S2K
    specifier MUST use a salt value, either a Salted S2K or an
    Iterated-Salted S2K.  The salt value will ensure that the decryption
    key is not repeated even if the passphrase is reused.
    """
    __ver__ = 4

    def __init__(self) -> None:
        super().__init__()
        self.ct = bytearray()

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        _bytes.append(self.symalg)
        _bytes += self.s2kspec.__bytearray__()
        _bytes += self.ct
        return _bytes

    def __copy__(self) -> SKESessionKeyV4:
        sk = self.__class__()
        sk.header = copy.copy(self.header)
        sk.s2kspec = copy.copy(self.s2kspec)
        sk.ct = self.ct[:]

        return sk

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)
        self.symalg = SymmetricKeyAlgorithm(packet[0])
        del packet[0]
        self.s2kspec.parse(packet)

        ctend = self.header.length - (2 + len(self.s2kspec))
        self.ct = packet[:ctend]
        del packet[:ctend]

    def decrypt_sk(self, passphrase: Union[str, bytes]) -> Tuple[Optional[SymmetricKeyAlgorithm], bytes]:
        # derive the first session key from our passphrase

        sk = self.s2kspec.derive_key(passphrase, self.symalg.key_size)
        del passphrase

        # if there is no ciphertext, then the first session key is the session key being used
        if len(self.ct) == 0:
            return self.symalg, sk

        # otherwise, we now need to decrypt the encrypted session key
        m = bytearray(_cfb_decrypt(bytes(self.ct), sk, self.symalg))
        del sk

        symalg = SymmetricKeyAlgorithm(m[0])
        del m[0]

        return symalg, bytes(m)

    def encrypt_sk(self, passphrase: Union[str, bytes], sk: ByteString) -> None:
        # derive the key to encrypt sk with from it (salt will be generated automatically if it is not yet set)
        esk = self.s2kspec.derive_key(passphrase, self.symalg.key_size)
        del passphrase

        # note that by default, we assume that we're using same
        # symmetric algorithm for the following SED or SEIPD packet.
        # This is a reasonable simplification for generation, but it
        # won't always be the same when parsing
        self.ct = _cfb_encrypt(self.int_to_bytes(self.symalg) + bytes(sk), esk, self.symalg)

        # update header length and return sk
        self.update_hlen()


class SKESessionKeyV6(SKESessionKey):
    '''
    From crypto-refresh-08:

    A version 6 Symmetric-Key Encrypted Session Key (SKESK) packet
    precedes a version 2 Symmetrically Encrypted Integrity Protected Data
    (v2 SEIPD, see Section 5.13.2) packet.  A v6 SKESK packet MUST NOT
    precede a v1 SEIPD packet or a deprecated Symmetrically Encrypted
    Data packet (see Section 11.3.2.1).

    A version 6 Symmetric-Key Encrypted Session Key packet consists of:

    *  A one-octet version number with value 6.

    *  A one-octet scalar octet count of the following 5 fields.

    *  A one-octet symmetric cipher algorithm identifier.

    *  A one-octet AEAD algorithm identifier.

    *  A one-octet scalar octet count of the following field.

    *  A string-to-key (S2K) specifier.  The length of the string-to-key
       specifier depends on its type (see Section 3.7.1).

    *  A starting initialization vector of size specified by the AEAD
       algorithm.

    *  The encrypted session key itself.

    *  An authentication tag for the AEAD mode.

    HKDF is used with SHA256 as hash algorithm, the key derived from S2K
    as Initial Keying Material (IKM), no salt, and the Packet Tag in the
    OpenPGP format encoding (bits 7 and 6 set, bits 5-0 carry the packet
    tag), the packet version, and the cipher-algo and AEAD-mode used to
    encrypt the key material, are used as info parameter.  Then, the
    session key is encrypted using the resulting key, with the AEAD
    algorithm specified for version 2 of the Symmetrically Encrypted
    Integrity Protected Data packet.  Note that no chunks are used and
    that there is only one authentication tag.  The Packet Tag in OpenPGP
    format encoding (bits 7 and 6 set, bits 5-0 carry the packet tag),
    the packet version number, the cipher algorithm octet, and the AEAD
    algorithm octet are given as additional data.  For example, the
    additional data used with AES-128 with OCB consists of the octets
    0xC3, 0x06, 0x07, and 0x02.
    '''
    __ver__ = 6

    def __init__(self) -> None:
        super().__init__()
        self._aead_algo: AEADMode = AEADMode.OCB
        self._iv: Optional[bytes] = None
        self._ct_and_tag: Optional[bytes] = None

    @property
    def iv(self) -> bytes:
        if self._iv is None:
            self._iv = os.urandom(self._aead_algo.iv_len)
        return self._iv

    def __bytearray__(self) -> bytearray:
        if self._ct_and_tag is None:
            raise ValueError("SKESK has not been fully initialized, cannot write")
        _bytes = bytearray()
        _bytes += super().__bytearray__()

        s2k_field: bytearray = self.s2kspec.__bytearray__()

        _bytes.append(3 + len(s2k_field) + self._aead_algo.iv_len)
        _bytes.append(self.symalg)
        _bytes.append(self._aead_algo)
        _bytes.append(len(s2k_field))
        _bytes += s2k_field
        _bytes += self.iv
        _bytes += self._ct_and_tag
        return _bytes

    def _get_info(self) -> bytes:
        'used for HKDF info and AEAD additional data'
        return bytes([0b11000000 + self.__typeid__, self.__ver__, int(self.symalg), int(self._aead_algo)])

    def _get_derived_key(self, passphrase: Union[str, bytes]) -> bytes:
        s2k_derived_key = self.s2kspec.derive_key(passphrase, self.symalg.key_size)
        hkdf = HKDF(algorithm=SHA256(), length=self.symalg.key_size // 8, salt=None, info=self._get_info())
        return hkdf.derive(s2k_derived_key)

    def _get_aead(self, passphrase: Union[str, bytes]) -> AEAD:
        derived_key = self._get_derived_key(passphrase)
        return AEAD(self.symalg, self._aead_algo, derived_key)

    def decrypt_sk(self, passphrase: Union[str, bytes]) -> Tuple[Optional[SymmetricKeyAlgorithm], bytes]:
        if self._iv is None or self._ct_and_tag is None:
            raise ValueError("SKESK is not fully initialized, cannot decrypt")
        aead = self._get_aead(passphrase)
        return None, aead.decrypt(nonce=self._iv, data=self._ct_and_tag, associated_data=self._get_info())

    def encrypt_sk(self, passphrase: Union[str, bytes], sk: ByteString) -> None:
        aead = self._get_aead(passphrase)
        self._ct_and_tag = aead.encrypt(nonce=self.iv, data=bytes(sk), associated_data=self._get_info())
        # update header length and return sk
        self.update_hlen()

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)
        param_len: int = packet[0]
        del packet[0]
        # FIXME: we should assert that the length of the packets up to but not including the ciphertext match this param_len count.

        self.symalg = SymmetricKeyAlgorithm(packet[0])
        del packet[0]

        self._aead_algo = AEADMode(packet[0])
        del packet[0]

        s2k_len = packet[0]
        del packet[0]

        self.s2kspec.parse(packet)

        self._iv = bytes(packet[:self._aead_algo.iv_len])
        del packet[:self._aead_algo.iv_len]

        # how do we know the size of the encrypted session key?
        # we cannot know this during this packet parsing alone, we assume it runs up through the tag length.
        # due to the cryptography module's AEAD interface, we do not separate out the tag from the ciphertext.
        ctlen = self.header.length - (param_len + 2)
        self._ct_and_tag = bytes(packet[:ctlen])
        del packet[:ctlen]


class OnePassSignature(VersionedPacket):
    '''Holds common members of various OPS packet versions'''
    __typeid__ = PacketType.OnePassSignature
    __ver__ = 0

    def __init__(self) -> None:
        super().__init__()
        self._sigtype: Optional[SignatureType] = None
        self._halg: Optional[HashAlgorithm] = None
        self._pubalg: Optional[PubKeyAlgorithm] = None
        self.nested: bool = False

    @sdproperty
    def sigtype(self) -> Optional[SignatureType]:
        return self._sigtype

    @sigtype.register
    def sigtype_int(self, val: int) -> None:
        if isinstance(val, SignatureType):
            self._sigtype = val
        else:
            self._sigtype = SignatureType(val)

    @sdproperty
    def pubalg(self) -> Optional[PubKeyAlgorithm]:
        return self._pubalg

    @pubalg.register
    def pubalg_int(self, val: int):
        if isinstance(val, PubKeyAlgorithm):
            self._pubalg = val
        else:
            self._pubalg = PubKeyAlgorithm(val)

    @sdproperty
    def halg(self) -> Optional[HashAlgorithm]:
        return self._halg

    @halg.register
    def halg_int(self, val: int) -> None:
        if isinstance(val, HashAlgorithm):
            self._halg = val
        else:
            self._halg = HashAlgorithm(val)
            if self._halg is HashAlgorithm.Unknown:
                self._opaque_halg: int = val

    @abc.abstractproperty
    def signer(self) -> Union[KeyID, Fingerprint]:
        raise NotImplementedError()

    @abc.abstractmethod
    def signer_set(self, val: Union[bytearray, bytes, str, KeyID, Fingerprint]) -> None:
        pass


class OnePassSignatureV3(OnePassSignature):
    """
    5.4.  One-Pass Signature Packets (Tag 4)

    The One-Pass Signature packet precedes the signed data and contains
    enough information to allow the receiver to begin calculating any
    hashes needed to verify the signature.  It allows the Signature
    packet to be placed at the end of the message, so that the signer
    can compute the entire signed message in one pass.

    A One-Pass Signature does not interoperate with PGP 2.6.x or
    earlier.

    The body of this packet consists of:

     - A one-octet version number.  The current version is 3.

     - A one-octet signature type.  Signature types are described in
       Section 5.2.1.

     - A one-octet number describing the hash algorithm used.

     - A one-octet number describing the public-key algorithm used.

     - An eight-octet number holding the Key ID of the signing key.

     - A one-octet number holding a flag showing whether the signature
       is nested.  A zero value indicates that the next packet is
       another One-Pass Signature packet that describes another
       signature to be applied to the same message data.

    Note that if a message contains more than one one-pass signature,
    then the Signature packets bracket the message; that is, the first
    Signature packet after the message corresponds to the last one-pass
    packet and the final Signature packet corresponds to the first
    one-pass packet.
    """
    __ver__ = 3

    @sdproperty
    def signer(self) -> KeyID:
        return self._signer

    @signer.register
    def signer_set(self, val: Union[bytearray, bytes, str, KeyID, Fingerprint]) -> None:
        self._signer = KeyID(val)

    def __init__(self) -> None:
        super().__init__()
        self._signer = KeyID(b'\x00' * 8)

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        _bytes.append(self.sigtype)
        if self.halg is HashAlgorithm.Unknown:
            _bytes.append(self._opaque_halg)
        else:
            _bytes.append(self.halg)
        _bytes.append(self.pubalg)
        _bytes += bytes(self.signer)
        _bytes.append(int(not self.nested))
        return _bytes

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)
        self.sigtype = packet[0]
        del packet[0]

        self.halg = packet[0]
        del packet[0]

        self.pubalg = packet[0]
        del packet[0]

        self.signer = packet[:8]
        del packet[:8]

        self.nested = (packet[0] == 0)
        del packet[0]


class PubKey(VersionedPacket, Primary, Public):
    __typeid__ = PacketType.PublicKey
    __ver__ = 0

    def __init__(self) -> None:
        super().__init__()
        self.created = datetime.now(timezone.utc)
        self.pkalg = 0
        self.keymaterial: Optional[PubKeyField] = None

    @abc.abstractproperty
    def fingerprint(self) -> Fingerprint:
        """compute and return the fingerprint of the key"""

    @sdproperty
    def created(self) -> datetime:
        return self._created

    @created.register
    def created_datetime(self, val: datetime) -> None:
        if val.tzinfo is None:
            warnings.warn("Passing TZ-naive datetime object to PubKeyV4 packet")
        self._created = val

    @created.register
    def created_int(self, val: int) -> None:
        self.created = datetime.fromtimestamp(val, timezone.utc)

    @created.register
    def created_bin(self, val: Union[bytes, bytearray]) -> None:
        self.created = self.bytes_to_int(val)

    @sdproperty
    def pkalg(self) -> PubKeyAlgorithm:
        return self._pkalg

    @pkalg.register
    def pkalg_int(self, val: int) -> None:
        if isinstance(val, PubKeyAlgorithm):
            self._pkalg: PubKeyAlgorithm = val
        else:
            self._pkalg = PubKeyAlgorithm(val)
            if self._pkalg is PubKeyAlgorithm.Unknown:
                self._opaque_pkalg: int = val

        if self.pkalg in {PubKeyAlgorithm.RSAEncryptOrSign, PubKeyAlgorithm.RSAEncrypt, PubKeyAlgorithm.RSASign}:
            self.keymaterial = RSAPub() if self.public else RSAPriv(self.__ver__)
        elif self.pkalg is PubKeyAlgorithm.DSA:
            self.keymaterial = DSAPub() if self.public else DSAPriv(self.__ver__)
        elif self.pkalg in {PubKeyAlgorithm.ElGamal, PubKeyAlgorithm.FormerlyElGamalEncryptOrSign}:
            self.keymaterial = ElGPub() if self.public else ElGPriv(self.__ver__)
        elif self.pkalg is PubKeyAlgorithm.ECDSA:
            self.keymaterial = ECDSAPub() if self.public else ECDSAPriv(self.__ver__)
        elif self.pkalg is PubKeyAlgorithm.ECDH:
            self.keymaterial = ECDHPub() if self.public else ECDHPriv(self.__ver__)
        elif self.pkalg is PubKeyAlgorithm.EdDSA:
            self.keymaterial = EdDSAPub() if self.public else EdDSAPriv(self.__ver__)
        else:
            self.keymaterial = OpaquePubKey() if self.public else OpaquePrivKey(self.__ver__)

    @property
    def public(self) -> bool:
        return isinstance(self, PubKey) and not isinstance(self, PrivKey)

    def __copy__(self) -> PubKey:
        pk = self.__class__()
        pk.header = copy.copy(self.header)
        pk.created = self.created
        if self.pkalg is PubKeyAlgorithm.Unknown:
            pk.pkalg = self._opaque_pkalg
        else:
            pk.pkalg = self.pkalg
        pk.keymaterial = copy.copy(self.keymaterial)

        return pk

    def verify(self, subj, sigbytes, hash_alg):
        return self.keymaterial.verify(subj, sigbytes, hash_alg)


class PubKeyV4(PubKey):
    __ver__ = 4

    @property
    def fingerprint(self) -> Fingerprint:
        if self.keymaterial is None:
            raise TypeError("Key material is not present, cannot calculate fingerprint")

        # A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99, followed by the two-octet packet length,
        # followed by the entire Public-Key packet starting with the version field.  The Key ID is the
        # low-order 64 bits of the fingerprint.
        fp = HashAlgorithm.SHA1.hasher

        plen = self.keymaterial.publen()
        bcde_len = self.int_to_bytes(6 + plen, 2)

        # a.1) 0x99 (1 octet)
        # a.2) high-order length octet
        # a.3) low-order length octet
        fp.update(b'\x99' + bcde_len[:1] + bcde_len[-1:])
        # b) version number = 4 (1 octet);
        fp.update(b'\x04')
        # c) timestamp of key creation (4 octets);
        fp.update(self.int_to_bytes(calendar.timegm(self.created.timetuple()), 4))
        # d) algorithm (1 octet): 17 = DSA (example);
        if self.pkalg is PubKeyAlgorithm.Unknown:
            fp.update(bytes([self._opaque_pkalg]))
        else:
            fp.update(self.int_to_bytes(self.pkalg))
        # e) Algorithm-specific fields.
        fp.update(self.keymaterial.__bytearray__()[:plen])

        # and return the digest
        return Fingerprint(fp.finalize(), version=4)

    def __init__(self) -> None:
        super().__init__()
        self.created = datetime.now(timezone.utc)

    def __bytearray__(self) -> bytearray:
        if self.keymaterial is None:
            raise TypeError("Key Material is missing, cannot produce bytearray")
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        _bytes += self.int_to_bytes(calendar.timegm(self.created.timetuple()), 4)
        if self.pkalg is PubKeyAlgorithm.Unknown:
            _bytes.append(self._opaque_pkalg)
        else:
            _bytes.append(self.pkalg)
        _bytes += self.keymaterial.__bytearray__()
        return _bytes

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)

        self.created = packet[:4]
        del packet[:4]

        self.pkalg = packet[0]
        del packet[0]

        # bound keymaterial to the remaining length of the packet
        pend = self.header.length - 6
        if self.keymaterial is not None:
            self.keymaterial.parse(packet[:pend])
        del packet[:pend]


class PrivKey(PubKey, Private):
    __typeid__ = PacketType.SecretKey
    __ver__ = 0

    @property
    def protected(self) -> bool:
        if not isinstance(self.keymaterial, PrivKeyField):
            return False
        return bool(self.keymaterial.s2k)

    @property
    def unlocked(self) -> bool:
        if self.keymaterial is None:
            return True
        if self.protected:
            return 0 not in list(self.keymaterial)
        return True  # pragma: no cover

    def protect(self, passphrase: str,
                enc_alg: Optional[SymmetricKeyAlgorithm] = None,
                hash_alg: Optional[HashAlgorithm] = None,
                s2kspec: Optional[S2KSpecifier] = None,
                iv: Optional[bytes] = None,
                aead_mode: Optional[AEADMode] = None) -> None:
        if enc_alg is None:
            enc_alg = SymmetricKeyAlgorithm.AES256
        if not isinstance(self.keymaterial, PrivKeyField):
            raise TypeError("Key material is not a private key, cannot protect")
        self.keymaterial.encrypt_keyblob(passphrase, enc_alg=enc_alg, hash_alg=hash_alg, s2kspec=s2kspec, iv=iv, aead_mode=aead_mode,
                                         packet_type=self.__typeid__,
                                         creation_time=self._created)
        del passphrase
        self.update_hlen()

    def unprotect(self, passphrase: Union[str, bytes]) -> None:
        if not isinstance(self.keymaterial, PrivKeyField):
            raise TypeError("Key material is not a private key, cannot unprotect")
        self.keymaterial.decrypt_keyblob(passphrase)
        del passphrase

    def sign(self, sigdata: bytes, hash_alg: HashAlgorithm) -> bytes:
        if not isinstance(self.keymaterial, PrivKeyField):
            raise TypeError("Key material is not a private key, cannot sign")
        return self.keymaterial.sign(sigdata, hash_alg)

    def _extract_pubkey(self, pk: PubKey) -> None:
        pk.created = self.created
        pk.pkalg = self.pkalg

        if self.keymaterial is not None:
            if pk.keymaterial is None:
                raise TypeError(f"pubkey material for {type(self.keymaterial)} was missing")
            # copy over MPIs
            for pm in self.keymaterial.__pubfields__:
                setattr(pk.keymaterial, pm, copy.copy(getattr(self.keymaterial, pm)))

            if isinstance(self.keymaterial, (ECDSAPub, EdDSAPub, ECDHPub)):
                if not isinstance(pk.keymaterial, (ECDSAPub, EdDSAPub, ECDHPub)):
                    raise TypeError(f"Expected Elliptic Curve, got {type(pk.keymaterial)} instead")
                pk.keymaterial.oid = self.keymaterial.oid

                if isinstance(self.keymaterial, ECDHPub):
                    if not isinstance(pk.keymaterial, ECDHPub):
                        raise TypeError(f"Expected ECDH, got {type(pk.keymaterial)} instead")
                    pk.keymaterial.kdf = copy.copy(self.keymaterial.kdf)

        pk.update_hlen()


class PrivKeyV4(PrivKey, PubKeyV4):
    __ver__ = 4

    @classmethod
    def new(cls, key_algorithm, key_size, created=None) -> PrivKeyV4:
        # build a key packet
        pk = PrivKeyV4()
        pk.pkalg = key_algorithm
        if pk.keymaterial is None:
            raise NotImplementedError(key_algorithm)
        if not isinstance(pk.keymaterial, PrivKeyField):
            raise TypeError("Key material is not a private key")
        pk.keymaterial._generate(key_size)
        if created is not None:
            pk.created = created
        pk.update_hlen()
        return pk

    def pubkey(self) -> Public:
        # return a copy of ourselves, but just the public half
        pk = PubKeyV4() if not isinstance(self, PrivSubKeyV4) else PubSubKeyV4()
        self._extract_pubkey(pk)
        return pk


class PrivSubKey(PrivKey, Sub):
    __typeid__ = PacketType.SecretSubKey
    __ver__ = 0


class PrivSubKeyV4(PrivSubKey, PrivKeyV4):
    __ver__ = 4


class CompressedData(Packet):
    """
    5.6.  Compressed Data Packet (Tag 8)

    The Compressed Data packet contains compressed data.  Typically, this
    packet is found as the contents of an encrypted packet, or following
    a Signature or One-Pass Signature packet, and contains a literal data
    packet.

    The body of this packet consists of:

     - One octet that gives the algorithm used to compress the packet.

     - Compressed data, which makes up the remainder of the packet.

    A Compressed Data Packet's body contains an block that compresses
    some set of packets.  See section "Packet Composition" for details on
    how messages are formed.

    ZIP-compressed packets are compressed with raw RFC 1951 [RFC1951]
    DEFLATE blocks.  Note that PGP V2.6 uses 13 bits of compression.  If
    an implementation uses more bits of compression, PGP V2.6 cannot
    decompress it.

    ZLIB-compressed packets are compressed with RFC 1950 [RFC1950] ZLIB-
    style blocks.

    BZip2-compressed packets are compressed using the BZip2 [BZ2]
    algorithm.
    """
    __typeid__ = PacketType.CompressedData

    @sdproperty
    def calg(self):
        return self._calg

    @calg.register(int)
    @calg.register(CompressionAlgorithm)
    def calg_int(self, val):
        self._calg = CompressionAlgorithm(val)

    def __init__(self):
        super().__init__()
        self._calg = None
        self.packets = []

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        _bytes += bytearray([self.calg])

        _pb = bytearray()
        for pkt in self.packets:
            _pb += pkt.__bytearray__()
        _bytes += self.calg.compress(bytes(_pb))

        return _bytes

    def parse(self, packet):
        super().parse(packet)
        self.calg = packet[0]
        del packet[0]

        cdata = bytearray(self.calg.decompress(packet[:self.header.length - 1]))
        del packet[:self.header.length - 1]

        while len(cdata) > 0:
            self.packets.append(Packet(cdata))


class SKEData(Packet):
    """
    5.7.  Symmetrically Encrypted Data Packet (Tag 9)

    The Symmetrically Encrypted Data packet contains data encrypted with
    a symmetric-key algorithm.  When it has been decrypted, it contains
    other packets (usually a literal data packet or compressed data
    packet, but in theory other Symmetrically Encrypted Data packets or
    sequences of packets that form whole OpenPGP messages).

    The body of this packet consists of:

     - Encrypted data, the output of the selected symmetric-key cipher
       operating in OpenPGP's variant of Cipher Feedback (CFB) mode.

    The symmetric cipher used may be specified in a Public-Key or
    Symmetric-Key Encrypted Session Key packet that precedes the
    Symmetrically Encrypted Data packet.  In that case, the cipher
    algorithm octet is prefixed to the session key before it is
    encrypted.  If no packets of these types precede the encrypted data,
    the IDEA algorithm is used with the session key calculated as the MD5
    hash of the passphrase, though this use is deprecated.

    The data is encrypted in CFB mode, with a CFB shift size equal to the
    cipher's block size.  The Initial Vector (IV) is specified as all
    zeros.  Instead of using an IV, OpenPGP prefixes a string of length
    equal to the block size of the cipher plus two to the data before it
    is encrypted.  The first block-size octets (for example, 8 octets for
    a 64-bit block length) are random, and the following two octets are
    copies of the last two octets of the IV.  For example, in an 8-octet
    block, octet 9 is a repeat of octet 7, and octet 10 is a repeat of
    octet 8.  In a cipher of length 16, octet 17 is a repeat of octet 15
    and octet 18 is a repeat of octet 16.  As a pedantic clarification,
    in both these examples, we consider the first octet to be numbered 1.

    After encrypting the first block-size-plus-two octets, the CFB state
    is resynchronized.  The last block-size octets of ciphertext are
    passed through the cipher and the block boundary is reset.

    The repetition of 16 bits in the random data prefixed to the message
    allows the receiver to immediately check whether the session key is
    incorrect.  See the "Security Considerations" section for hints on
    the proper use of this "quick check".
    """
    __typeid__ = PacketType.SymmetricallyEncryptedData

    def __init__(self):
        super().__init__()
        self.ct = bytearray()

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        _bytes += self.ct
        return _bytes

    def __copy__(self):
        skd = self.__class__()
        skd.ct = self.ct[:]
        return skd

    def parse(self, packet):
        super().parse(packet)
        self.ct = packet[:self.header.length]
        del packet[:self.header.length]

    def decrypt(self, key: bytes, alg: Optional[SymmetricKeyAlgorithm]) -> bytearray:  # pragma: no cover
        if alg is None:
            raise TypeError("SED cannot decrypt without knowing the symmetric algorithm")
        block_size_bytes = alg.block_size // 8
        pt_prefix = _cfb_decrypt(bytes(self.ct[:block_size_bytes + 2]), bytes(key), alg)

        # old Symmetrically Encrypted Data Packet required
        # to change iv after decrypting prefix
        iv_resync = bytes(self.ct[2:block_size_bytes + 2])

        iv = bytes(pt_prefix[:block_size_bytes])
        del pt_prefix[:block_size_bytes]

        ivl2 = bytes(pt_prefix[:2])

        if not constant_time.bytes_eq(iv[-2:], ivl2):
            raise PGPDecryptionError("Decryption failed")

        pt = _cfb_decrypt(bytes(self.ct[block_size_bytes + 2:]), bytes(key), alg, iv=iv_resync)

        return pt


class Marker(Packet):
    __typeid__ = PacketType.Marker

    def __init__(self):
        super().__init__()
        self.data = b'PGP'

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        _bytes += self.data
        return _bytes

    def parse(self, packet):
        super().parse(packet)
        self.data = packet[:self.header.length]
        del packet[:self.header.length]


class Padding(Packet):
    __typeid__ = PacketType.Padding

    def __init__(self) -> None:
        super().__init__()
        self.data: bytes = b''

    @sdproperty
    def size(self) -> int:
        'The full size of the packet in its standard form'
        return self.header.length + 2

    @size.register
    def size_int(self, val: int) -> None:
        if val < 2:
            raise ValueError(f"padding needs to be at least 2 octets, not {val}")
        self.data = os.urandom(val - 2)
        self.update_hlen()

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        _bytes += self.data
        return _bytes

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)
        self.data = packet[:self.header.length]
        del packet[:self.header.length]


class LiteralData(Packet):
    """
    5.9.  Literal Data Packet (Tag 11)

    A Literal Data packet contains the body of a message; data that is
    not to be further interpreted.

    The body of this packet consists of:

     - A one-octet field that describes how the data is formatted.

    If it is a 'b' (0x62), then the Literal packet contains binary data.
    If it is a 't' (0x74), then it contains text data, and thus may need
    line ends converted to local form, or other text-mode changes.  The
    tag 'u' (0x75) means the same as 't', but also indicates that
    implementation believes that the literal data contains UTF-8 text.

    Early versions of PGP also defined a value of 'l' as a 'local' mode
    for machine-local conversions.  RFC 1991 [RFC1991] incorrectly stated
    this local mode flag as '1' (ASCII numeral one).  Both of these local
    modes are deprecated.

     - File name as a string (one-octet length, followed by a file
       name).  This may be a zero-length string.  Commonly, if the
       source of the encrypted data is a file, this will be the name of
       the encrypted file.  An implementation MAY consider the file name
       in the Literal packet to be a more authoritative name than the
       actual file name.

    If the special name "_CONSOLE" is used, the message is considered to
    be "for your eyes only".  This advises that the message data is
    unusually sensitive, and the receiving program should process it more
    carefully, perhaps avoiding storing the received data to disk, for
    example.

     - A four-octet number that indicates a date associated with the
       literal data.  Commonly, the date might be the modification date
       of a file, or the time the packet was created, or a zero that
       indicates no specific time.

     - The remainder of the packet is literal data.

       Text data is stored with <CR><LF> text endings (i.e., network-
       normal line endings).  These should be converted to native line
       endings by the receiving software.
    """
    __typeid__ = PacketType.LiteralData

    @sdproperty
    def mtime(self):
        return self._mtime

    @mtime.register(datetime)
    def mtime_datetime(self, val):
        if val.tzinfo is None:
            warnings.warn("Passing TZ-naive datetime object to LiteralData packet")
        self._mtime = val

    @mtime.register(int)
    def mtime_int(self, val):
        self.mtime = datetime.fromtimestamp(val, timezone.utc)

    @mtime.register(bytes)
    @mtime.register(bytearray)
    def mtime_bin(self, val):
        self.mtime = self.bytes_to_int(val)

    @property
    def contents(self):
        if self.format == 't':
            return self._contents.decode('latin-1')

        if self.format == 'u':
            return self._contents.decode('utf-8')

        return self._contents

    def __init__(self):
        super().__init__()
        self.format = 'b'
        self.filename = ''
        self.mtime = datetime.now(timezone.utc)
        self._contents = bytearray()

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        _bytes += self.format.encode('latin-1')
        _bytes += bytearray([len(self.filename)])
        _bytes += self.filename.encode('latin-1')
        _bytes += self.int_to_bytes(calendar.timegm(self.mtime.timetuple()), 4)
        _bytes += self._contents
        return _bytes

    def __copy__(self):
        pkt = LiteralData()
        pkt.header = copy.copy(self.header)
        pkt.format = self.format
        pkt.filename = self.filename
        pkt.mtime = self.mtime
        pkt._contents = self._contents[:]

        return pkt

    def parse(self, packet):
        super().parse(packet)
        self.format = chr(packet[0])
        del packet[0]

        fnl = packet[0]
        del packet[0]

        self.filename = packet[:fnl].decode()
        del packet[:fnl]

        self.mtime = packet[:4]
        del packet[:4]

        self._contents = packet[:self.header.length - (6 + fnl)]
        del packet[:self.header.length - (6 + fnl)]


class Trust(Packet):
    """
    5.10.  Trust Packet (Tag 12)

    The Trust packet is used only within keyrings and is not normally
    exported.  Trust packets contain data that record the user's
    specifications of which key holders are trustworthy introducers,
    along with other information that implementing software uses for
    trust information.  The format of Trust packets is defined by a given
    implementation.

    Trust packets SHOULD NOT be emitted to output streams that are
    transferred to other users, and they SHOULD be ignored on any input
    other than local keyring files.
    """
    __typeid__ = PacketType.Trust

    @sdproperty
    def trustlevel(self):
        return self._trustlevel

    @trustlevel.register(int)
    @trustlevel.register(TrustLevel)
    def trustlevel_int(self, val):
        self._trustlevel = TrustLevel(val & 0x0F)

    @sdproperty
    def trustflags(self):
        return self._trustflags

    @trustflags.register(list)
    def trustflags_list(self, val):
        self._trustflags = TrustFlags(sum(val))

    @trustflags.register
    def trustflags_int(self, val: Union[int, TrustFlags]):
        if not isinstance(val, TrustFlags):
            val = TrustFlags(val)
        self._trustflags = val

    def __init__(self):
        super().__init__()
        self.trustlevel = TrustLevel.Unknown
        self.trustflags = []

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        _bytes += self.int_to_bytes(self.trustlevel + sum(self.trustflags), 2)
        return _bytes

    def parse(self, packet):
        super().parse(packet)
        # self.trustlevel = packet[0] & 0x1f
        t = self.bytes_to_int(packet[:2])
        del packet[:2]

        self.trustlevel = t
        self.trustflags = t


class UserID(Packet):
    """
    5.11.  User ID Packet (Tag 13)

    A User ID packet consists of UTF-8 text that is intended to represent
    the name and email address of the key holder.  By convention, it
    includes an RFC 2822 [RFC2822] mail name-addr, but there are no
    restrictions on its content.  The packet length in the header
    specifies the length of the User ID.
    """
    __typeid__ = PacketType.UserID

    def __init__(self, uid=""):
        super().__init__()
        self.uid = uid
        self._encoding_fallback = False

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        textenc = 'utf-8' if not self._encoding_fallback else 'charmap'
        _bytes += self.uid.encode(textenc)

        return _bytes

    def __copy__(self):
        uid = UserID()
        uid.header = copy.copy(self.header)
        uid.uid = self.uid
        return uid

    def parse(self, packet):
        super().parse(packet)

        uid_bytes = packet[:self.header.length]
        # uid_text = packet[:self.header.length].decode('utf-8')
        del packet[:self.header.length]
        try:
            self.uid = uid_bytes.decode('utf-8')
        except UnicodeDecodeError:
            self.uid = uid_bytes.decode('charmap')
            self._encoding_fallback = True


class PubSubKey(VersionedPacket, Sub, Public):
    __typeid__ = PacketType.PublicSubKey
    __ver__ = 0


class PubSubKeyV4(PubSubKey, PubKeyV4):
    __ver__ = 4


class UserAttribute(Packet):
    """
    5.12.  User Attribute Packet (Tag 17)

    The User Attribute packet is a variation of the User ID packet.  It
    is capable of storing more types of data than the User ID packet,
    which is limited to text.  Like the User ID packet, a User Attribute
    packet may be certified by the key owner ("self-signed") or any other
    key owner who cares to certify it.  Except as noted, a User Attribute
    packet may be used anywhere that a User ID packet may be used.

    While User Attribute packets are not a required part of the OpenPGP
    standard, implementations SHOULD provide at least enough
    compatibility to properly handle a certification signature on the
    User Attribute packet.  A simple way to do this is by treating the
    User Attribute packet as a User ID packet with opaque contents, but
    an implementation may use any method desired.

    The User Attribute packet is made up of one or more attribute
    subpackets.  Each subpacket consists of a subpacket header and a
    body.  The header consists of:

     - the subpacket length (1, 2, or 5 octets)

     - the subpacket type (1 octet)

    and is followed by the subpacket specific data.

    The only currently defined subpacket type is 1, signifying an image.
    An implementation SHOULD ignore any subpacket of a type that it does
    not recognize.  Subpacket types 100 through 110 are reserved for
    private or experimental use.
    """
    __typeid__ = PacketType.UserAttribute

    @property
    def image(self):
        if 'Image' not in self.subpackets:
            self.subpackets.addnew('Image')
        return next(iter(self.subpackets['Image']))

    def __init__(self):
        super().__init__()
        self.subpackets = UserAttributeSubPackets()

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        _bytes += self.subpackets.__bytearray__()
        return _bytes

    def parse(self, packet):
        super().parse(packet)

        plen = len(packet)
        while self.header.length > (plen - len(packet)):
            self.subpackets.parse(packet)

    def update_hlen(self):
        self.subpackets.update_hlen()
        super().update_hlen()


class IntegrityProtectedSKEData(VersionedPacket):
    __typeid__ = PacketType.SymmetricallyEncryptedIntegrityProtectedData
    __ver__ = 0

    @abc.abstractmethod
    def decrypt(self, key: bytes, alg: Optional[SymmetricKeyAlgorithm]) -> bytearray:
        raise NotImplementedError()


class IntegrityProtectedSKEDataV1(IntegrityProtectedSKEData):
    """
    5.13.  Sym. Encrypted Integrity Protected Data Packet (Tag 18)

    The Symmetrically Encrypted Integrity Protected Data packet is a
    variant of the Symmetrically Encrypted Data packet.  It is a new
    feature created for OpenPGP that addresses the problem of detecting a
    modification to encrypted data.  It is used in combination with a
    Modification Detection Code packet.

    There is a corresponding feature in the features Signature subpacket
    that denotes that an implementation can properly use this packet
    type.  An implementation MUST support decrypting these packets and
    SHOULD prefer generating them to the older Symmetrically Encrypted
    Data packet when possible.  Since this data packet protects against
    modification attacks, this standard encourages its proliferation.
    While blanket adoption of this data packet would create
    interoperability problems, rapid adoption is nevertheless important.
    An implementation SHOULD specifically denote support for this packet,
    but it MAY infer it from other mechanisms.

    For example, an implementation might infer from the use of a cipher
    such as Advanced Encryption Standard (AES) or Twofish that a user
    supports this feature.  It might place in the unhashed portion of
    another user's key signature a Features subpacket.  It might also
    present a user with an opportunity to regenerate their own self-
    signature with a Features subpacket.

    This packet contains data encrypted with a symmetric-key algorithm
    and protected against modification by the SHA-1 hash algorithm.  When
    it has been decrypted, it will typically contain other packets (often
    a Literal Data packet or Compressed Data packet).  The last decrypted
    packet in this packet's payload MUST be a Modification Detection Code
    packet.

    The body of this packet consists of:

     - A one-octet version number.  The only currently defined value is
       1.

     - Encrypted data, the output of the selected symmetric-key cipher
       operating in Cipher Feedback mode with shift amount equal to the
       block size of the cipher (CFB-n where n is the block size).

    The symmetric cipher used MUST be specified in a Public-Key or
    Symmetric-Key Encrypted Session Key packet that precedes the
    Symmetrically Encrypted Data packet.  In either case, the cipher
    algorithm octet is prefixed to the session key before it is
    encrypted.

    The data is encrypted in CFB mode, with a CFB shift size equal to the
    cipher's block size.  The Initial Vector (IV) is specified as all
    zeros.  Instead of using an IV, OpenPGP prefixes an octet string to
    the data before it is encrypted.  The length of the octet string
    equals the block size of the cipher in octets, plus two.  The first
    octets in the group, of length equal to the block size of the cipher,
    are random; the last two octets are each copies of their 2nd
    preceding octet.  For example, with a cipher whose block size is 128
    bits or 16 octets, the prefix data will contain 16 random octets,
    then two more octets, which are copies of the 15th and 16th octets,
    respectively.  Unlike the Symmetrically Encrypted Data Packet, no
    special CFB resynchronization is done after encrypting this prefix
    data.  See "OpenPGP CFB Mode" below for more details.

    The repetition of 16 bits in the random data prefixed to the message
    allows the receiver to immediately check whether the session key is
    incorrect.

    The plaintext of the data to be encrypted is passed through the SHA-1
    hash function, and the result of the hash is appended to the
    plaintext in a Modification Detection Code packet.  The input to the
    hash function includes the prefix data described above; it includes
    all of the plaintext, and then also includes two octets of values
    0xD3, 0x14.  These represent the encoding of a Modification Detection
    Code packet tag and length field of 20 octets.

    The resulting hash value is stored in a Modification Detection Code
    (MDC) packet, which MUST use the two octet encoding just given to
    represent its tag and length field.  The body of the MDC packet is
    the 20-octet output of the SHA-1 hash.

    The Modification Detection Code packet is appended to the plaintext
    and encrypted along with the plaintext using the same CFB context.

    During decryption, the plaintext data should be hashed with SHA-1,
    including the prefix data as well as the packet tag and length field
    of the Modification Detection Code packet.  The body of the MDC
    packet, upon decryption, is compared with the result of the SHA-1
    hash.

    Any failure of the MDC indicates that the message has been modified
    and MUST be treated as a security problem.  Failures include a
    difference in the hash values, but also the absence of an MDC packet,
    or an MDC packet in any position other than the end of the plaintext.
    Any failure SHOULD be reported to the user.

    Note: future designs of new versions of this packet should consider
    rollback attacks since it will be possible for an attacker to change
    the version back to 1.
    """
    __ver__ = 1

    def __init__(self):
        super().__init__()
        self.ct = bytearray()

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        _bytes += self.ct
        return _bytes

    def __copy__(self):
        skd = self.__class__()
        skd.ct = self.ct[:]
        return skd

    def parse(self, packet):
        super().parse(packet)
        self.ct = packet[:self.header.length - 1]
        del packet[:self.header.length - 1]

    def encrypt(self, key, alg, data, iv: Optional[bytes] = None):
        if iv is None:
            iv = alg.gen_iv()
        data = iv + iv[-2:] + data

        mdc = MDC()
        mdc.mdc = binascii.hexlify(HashAlgorithm.SHA1.digest(data + b'\xd3\x14'))
        mdc.update_hlen()

        data += mdc.__bytes__()
        self.ct = _cfb_encrypt(data, key, alg)
        self.update_hlen()

    def decrypt(self, key: bytes, alg: Optional[SymmetricKeyAlgorithm]) -> bytearray:
        if alg is None:
            raise TypeError("SEIPDv1 cannot decrypt without knowing the symmetric algorithm")
        # iv, ivl2, pt = super(IntegrityProtectedSKEDataV1, self).decrypt(key, alg)
        pt = _cfb_decrypt(bytes(self.ct), bytes(key), alg)

        # do the MDC checks
        _expected_mdcbytes = b'\xd3\x14' + HashAlgorithm.SHA1.digest(pt[:-20])
        if not constant_time.bytes_eq(bytes(pt[-22:]), _expected_mdcbytes):
            raise PGPDecryptionError("Decryption failed")  # pragma: no cover

        iv = bytes(pt[:alg.block_size // 8])
        del pt[:alg.block_size // 8]

        ivl2 = bytes(pt[:2])
        del pt[:2]

        if not constant_time.bytes_eq(iv[-2:], ivl2):
            raise PGPDecryptionError("Decryption failed")  # pragma: no cover

        return pt


class IntegrityProtectedSKEDataV2(IntegrityProtectedSKEData):
    __ver__ = 2

    def __init__(self) -> None:
        super().__init__()
        self.cipher: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES128
        self.aead: AEADMode = AEADMode.OCB
        self._chunksize: int = 6
        self._salt: Optional[bytearray] = None
        self.ct: bytearray = bytearray()
        self.final_tag: bytearray = bytearray()

    @sdproperty
    def chunksize(self) -> int:
        'The numeric value of chunksize, as opposed to the octet stored on the wire'
        return 1 << (self._chunksize + 6)

    @chunksize.register
    def chunksize_int(self, val: int) -> None:
        n = int(log2(val)) - 6
        if n < 0:
            raise ValueError(f"AEAD chunksize cannot be less than {1 << 6}")
        if n > 16:
            raise ValueError(f"AEAD chunksize cannot be more than {1 << 22}")
        if 1 << (n + 6) != val:
            raise ValueError(f"AEAD chunksize must be a power of 2")
        self._chunksize = n

    @sdproperty
    def salt(self) -> bytearray:
        if self._salt is None:
            self._salt = bytearray(os.urandom(32))
        return self._salt

    @salt.register
    def salt_set(self, val: Union[bytes, bytearray]) -> None:
        if len(val) != 32:
            raise ValueError(f"SEIPDv2 expected 32-octet salt, got {len(val)} octets")
        self._salt = bytearray(val)

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes += super().__bytearray__()
        _bytes.append(int(self.cipher))
        _bytes.append(int(self.aead))
        _bytes.append(int(self._chunksize))
        _bytes += self.salt
        _bytes += self.ct
        _bytes += self.final_tag
        return _bytes

    def __copy__(self) -> IntegrityProtectedSKEDataV2:
        skd = IntegrityProtectedSKEDataV2()
        skd.cipher = self.cipher
        skd.aead = self.aead
        skd._chunksize = self._chunksize
        skd.salt = self.salt[:]
        skd.ct = self.ct[:]
        skd.final_tag = self.final_tag[:]
        return skd

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)
        self.cipher = SymmetricKeyAlgorithm(packet[0])
        del packet[0]
        self.aead = AEADMode(packet[0])
        del packet[0]
        self._chunksize = packet[0]
        del packet[0]
        self.salt = packet[:32]
        del packet[:32]

        remainder = self.header.length - 36
        # we need both the final tag, and we need at least one full
        # tag length in the main ciphertext itself:
        minlen = 2 * self.aead.tag_len
        if remainder < minlen:
            raise ValueError(f"Not enough material for an SEIPD v2 packet using {self.aead!r}: expected at least {minlen} octets, got {remainder}")
        self.ct = packet[:remainder - self.aead.tag_len]
        del packet[:remainder - self.aead.tag_len]
        self.final_tag = packet[:self.aead.tag_len]
        del packet[:self.aead.tag_len]

    def _get_info(self) -> bytes:
        'the info parameter used for HKDF and AEAD'
        return bytes([0b11000000 + self.__typeid__, self.__ver__, int(self.cipher), int(self.aead), self._chunksize])

    def _get_aead_and_iv(self, session_key: bytes) -> Tuple[AEAD, bytes]:
        ivlen = self.aead.iv_len - 8
        keylen = self.cipher.key_size // 8
        hkdf = HKDF(algorithm=SHA256(), length=keylen + ivlen, salt=bytes(self.salt), info=self._get_info())
        hkdf_output = hkdf.derive(session_key)
        key = bytes(hkdf_output[:keylen])
        iv = bytes(hkdf_output[keylen:])
        aead = AEAD(self.cipher, self.aead, key)
        return (aead, iv)

    def encrypt(self, key: bytes, data: bytes) -> None:
        aead, iv = self._get_aead_and_iv(key)
        ad = self._get_info()
        new_ct: bytearray = bytearray()
        chunk_index: int = 0
        # handle the chunks:
        for offset in range(0, len(data), self.chunksize):
            chunk: bytes = data[offset:offset + self.chunksize]
            nonce: bytes = iv + self.int_to_bytes(chunk_index, 8)
            new_ct += aead.encrypt(nonce, chunk, associated_data=ad)
            chunk_index += 1

        self.ct = new_ct
        nonce = iv + self.int_to_bytes(chunk_index, 8)
        self.final_tag += aead.encrypt(nonce, b'', associated_data=ad + self.int_to_bytes(len(data), 8))
        self.update_hlen()

    def decrypt(self, key: bytes, algo: Optional[SymmetricKeyAlgorithm] = None) -> bytearray:
        if algo is not None:
            raise PGPDecryptionError(
                f"v2 SEIPD knows its own algorithm ({self.cipher!r}), should not be explicitly passed one, but it got {algo!r} (maybe v3 PKESK or v4 SKESK precedes it instead of v6?)")
        aead, iv = self._get_aead_and_iv(key)
        ad = self._get_info()
        cleartext: bytearray = bytearray()
        chunk_index: int = 0
        # handle the chunks:
        for offset in range(0, len(self.ct), self.chunksize + self.aead.tag_len):
            chunk: bytes = bytes(self.ct[offset:offset + self.chunksize + self.aead.tag_len])
            nonce: bytes = iv + self.int_to_bytes(chunk_index, 8)
            cleartext += aead.decrypt(nonce, chunk, associated_data=ad)
            chunk_index += 1

        nonce = iv + self.int_to_bytes(chunk_index, 8)
        final_check: bytes = aead.decrypt(nonce, bytes(self.final_tag), associated_data=ad + self.int_to_bytes(len(cleartext), 8))
        if final_check != b'':
            raise PGPDecryptionError("AEAD final tag was not made over the empty string")
        return cleartext


class MDC(Packet):
    """
    5.14.  Modification Detection Code Packet (Tag 19)

    The Modification Detection Code packet contains a SHA-1 hash of
    plaintext data, which is used to detect message modification.  It is
    only used with a Symmetrically Encrypted Integrity Protected Data
    packet.  The Modification Detection Code packet MUST be the last
    packet in the plaintext data that is encrypted in the Symmetrically
    Encrypted Integrity Protected Data packet, and MUST appear in no
    other place.

    A Modification Detection Code packet MUST have a length of 20 octets.
    The body of this packet consists of:

     - A 20-octet SHA-1 hash of the preceding plaintext data of the
       Symmetrically Encrypted Integrity Protected Data packet,
       including prefix data, the tag octet, and length octet of the
       Modification Detection Code packet.

    Note that the Modification Detection Code packet MUST always use a
    new format encoding of the packet tag, and a one-octet encoding of
    the packet length.  The reason for this is that the hashing rules for
    modification detection include a one-octet tag and one-octet length
    in the data hash.  While this is a bit restrictive, it reduces
    complexity.
    """
    __typeid__ = PacketType.ModificationDetectionCode

    def __init__(self):
        super().__init__()
        self.mdc = ''

    def __bytearray__(self):
        return super().__bytearray__() + binascii.unhexlify(self.mdc)

    def parse(self, packet):
        super().parse(packet)
        self.mdc = binascii.hexlify(packet[:20])
        del packet[:20]
