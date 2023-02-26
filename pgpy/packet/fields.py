""" fields.py
"""
from __future__ import annotations

import abc
import binascii
import collections
import copy
import itertools
import math
import os

import collections.abc
from datetime import datetime

from typing import Optional, Tuple, Type, Union

from warnings import warn

from argon2.low_level import hash_secret_raw  # type: ignore
from argon2 import Type as ArgonType  # type: ignore

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256, SHA512, HashAlgorithm as cryptography_HashAlgorithm

from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

from cryptography.hazmat.primitives.padding import PKCS7

from .subpackets import Signature as SignatureSP
from .subpackets import UserAttribute
from .subpackets import signature
from .subpackets import userattribute

from .subpackets.types import SubPacket

from .types import MPI
from .types import MPIs

from ..constants import EllipticCurveOID
from ..constants import ECPointFormat
from ..constants import PacketType
from ..constants import HashAlgorithm
from ..constants import PubKeyAlgorithm
from ..constants import String2KeyType
from ..constants import S2KGNUExtension
from ..constants import SymmetricKeyAlgorithm
from ..constants import S2KUsage
from ..constants import AEADMode

from ..decorators import sdproperty

from ..errors import PGPDecryptionError
from ..errors import PGPError
from ..errors import PGPIncompatibleECPointFormatError

from ..symenc import _cfb_decrypt
from ..symenc import _cfb_encrypt
from ..symenc import AEAD

from ..types import Field
from ..types import Fingerprint

__all__ = ['SubPackets',
           'UserAttributeSubPackets',
           'Signature',
           'OpaqueSignature',
           'RSASignature',
           'DSASignature',
           'ECDSASignature',
           'EdDSASignature',
           'Ed25519Signature',
           'Ed448Signature',
           'PubKey',
           'OpaquePubKey',
           'RSAPub',
           'DSAPub',
           'ElGPub',
           'ECPoint',
           'ECDSAPub',
           'EdDSAPub',
           'Ed25519Pub',
           'Ed448Pub',
           'ECDHPub',
           'X25519Pub',
           'X448Pub',
           'S2KSpecifier',
           'String2Key',
           'ECKDF',
           'NativeEdDSAPub',
           'NativeEdDSAPriv',
           'NativeEdDSASignature',
           'NativeCFRGXPriv',
           'NativeCFRGXPub',
           'NativeCFRGXCipherText',
           'PrivKey',
           'OpaquePrivKey',
           'RSAPriv',
           'DSAPriv',
           'ElGPriv',
           'ECDSAPriv',
           'EdDSAPriv',
           'Ed25519Priv',
           'Ed448Priv',
           'ECDHPriv',
           'X25519Priv',
           'X448Priv',
           'CipherText',
           'RSACipherText',
           'ElGCipherText',
           'ECDHCipherText',
           'X25519CipherText',
           'X448CipherText',
           ]


class SubPackets(collections.abc.MutableMapping[str, SubPacket], Field):
    _spmodule = signature

    def __init__(self, width: int = 2) -> None:
        super().__init__()
        self._hashed_sp: collections.OrderedDict[str, SubPacket] = collections.OrderedDict()
        self._unhashed_sp: collections.OrderedDict[str, SubPacket] = collections.OrderedDict()
        # self._width represents how wide the size field is when these
        # subpackets are put on the wire.  v4 subpackets use a width
        # of 2.  newer subpackets use a width of 4.
        self._width = width

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes += self.__hashbytearray__()
        _bytes += self.__unhashbytearray__()
        return _bytes

    def __hashbytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes += self.int_to_bytes(sum(len(sp) for sp in self._hashed_sp.values()), self._width)
        for hsp in self._hashed_sp.values():
            _bytes += hsp.__bytearray__()
        return _bytes

    def __unhashbytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes += self.int_to_bytes(sum(len(sp) for sp in self._unhashed_sp.values()), self._width)
        for uhsp in self._unhashed_sp.values():
            _bytes += uhsp.__bytearray__()
        return _bytes

    def __len__(self) -> int:  # pragma: no cover
        return sum(sp.header.length for sp in itertools.chain(self._hashed_sp.values(), self._unhashed_sp.values())) + 4

    def __iter__(self):
        yield from itertools.chain(self._hashed_sp.values(), self._unhashed_sp.values())

    def __setitem__(self, key, val):
        # the key provided should always be the classname for the subpacket
        # but, there can be multiple subpackets of the same type
        # so, it should be stored in the format: [h_]<key>_<seqid>
        # where:
        #  - <key> is the classname of val
        #  - <seqid> is a sequence id, starting at 0, for a given classname

        i = 0
        if isinstance(key, tuple):  # pragma: no cover
            key, i = key

        d = self._unhashed_sp
        if key.startswith('h_'):
            d, key = self._hashed_sp, key[2:]

        while (key, i) in d:
            i += 1

        d[(key, i)] = val

    def __getitem__(self, key):
        if isinstance(key, tuple):  # pragma: no cover
            return self._hashed_sp.get(key, self._unhashed_sp.get(key))

        if key.startswith('h_'):
            return [v for k, v in self._hashed_sp.items() if key[2:] == k[0]]

        else:
            return [v for k, v in itertools.chain(self._hashed_sp.items(), self._unhashed_sp.items()) if key == k[0]]

    def __delitem__(self, key):
        ##TODO: this
        raise NotImplementedError()

    def __contains__(self, key):
        return key in {k for k, _ in itertools.chain(self._hashed_sp, self._unhashed_sp)}

    def __copy__(self):
        sp = SubPackets(self._width)
        sp._hashed_sp = self._hashed_sp.copy()
        sp._unhashed_sp = self._unhashed_sp.copy()

        return sp

    def addnew(self, spname: str, hashed: bool = False, critical: bool = False, **kwargs) -> None:
        nsp = getattr(self._spmodule, spname)()
        if critical:
            nsp.header.critical = True
        for p, v in kwargs.items():
            if hasattr(nsp, p):
                setattr(nsp, p, v)
            else:
                warn(f"subpacket {spname} does not have attr {p}")
        nsp.update_hlen()
        if hashed:
            self['h_' + spname] = nsp
            # remove unhashed version of this subpacket -- we do not want a conflict
            unhashed_subpackets = list(filter(lambda x: x[0] == spname, self._unhashed_sp.keys()))
            for unhashed_subpacket in unhashed_subpackets:
                del self._unhashed_sp[unhashed_subpacket]
        else:
            self[spname] = nsp

    def update_hlen(self):
        for sp in self:
            sp.update_hlen()

    def _normalize(self) -> None:
        '''Order subpackets by subpacket ID

        This private interface must only be called a Subpackets object
        before it is signed, otherwise it will break the signature

        '''
        self._hashed_sp = collections.OrderedDict(sorted(self._hashed_sp.items(), key=lambda x: (x[1].__typeid__, x[0][1])))
        self._unhashed_sp = collections.OrderedDict(sorted(self._unhashed_sp.items(), key=lambda x: (x[1].__typeid__, x[0][1])))

    def parse(self, packet: bytearray) -> None:
        hl = self.bytes_to_int(packet[:self._width])
        del packet[:self._width]

        # we do it this way because we can't ensure that subpacket headers are sized appropriately
        # for their contents, but we can at least output that correctly
        # so instead of tracking how many bytes we can now output, we track how many bytes have we parsed so far
        plen = len(packet)
        while plen - len(packet) < hl:
            sp = SignatureSP(packet)  # type: ignore[abstract]
            self['h_' + sp.__class__.__name__] = sp

        uhl = self.bytes_to_int(packet[:self._width])
        del packet[:self._width]

        plen = len(packet)
        while plen - len(packet) < uhl:
            sp = SignatureSP(packet)  # type: ignore[abstract]
            self[sp.__class__.__name__] = sp


class UserAttributeSubPackets(SubPackets):
    """
    This is nearly the same as just the unhashed subpackets from above,
    except that there isn't a length specifier. So, parse will only parse one packet,
    appending that one packet to self.__unhashed_sp.
    """
    _spmodule = userattribute

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        for uhsp in self._unhashed_sp.values():
            _bytes += uhsp.__bytearray__()
        return _bytes

    def __len__(self) -> int:  # pragma: no cover
        return sum(len(sp) for sp in self._unhashed_sp.values())

    def parse(self, packet: bytearray) -> None:
        # parse just one packet and add it to the unhashed subpacket ordereddict
        # I actually have yet to come across a User Attribute packet with more than one subpacket
        # which makes sense, given that there is only one defined subpacket
        sp = UserAttribute(packet)  # type: ignore[abstract]
        self[sp.__class__.__name__] = sp


class Signature(MPIs):
    def __init__(self) -> None:
        for i in self.__mpis__:
            setattr(self, i, MPI(0))

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        for i in self:
            _bytes += i.to_mpibytes()
        return _bytes

    @abc.abstractproperty
    def __sig__(self):
        """return the signature bytes in a format that can be understood by the signature verifier"""

    @abc.abstractmethod
    def from_signer(self, sig):
        """create and parse a concrete Signature class instance"""


class OpaqueSignature(Signature):
    def __init__(self) -> None:
        super().__init__()
        self.data = bytearray()

    def __bytearray__(self) -> bytearray:
        return self.data

    def __sig__(self):
        return self.data

    def parse(self, packet: bytearray) -> None:
        self.data = packet

    def from_signer(self, sig):
        self.data = bytearray(sig)


class RSASignature(Signature):
    __mpis__ = ('md_mod_n', )

    def __sig__(self):
        return self.md_mod_n.to_mpibytes()[2:]

    def parse(self, packet: bytearray) -> None:
        self.md_mod_n = MPI(packet)

    def from_signer(self, sig):
        self.md_mod_n = MPI(self.bytes_to_int(sig))


class DSASignature(Signature):
    __mpis__ = ('r', 's')

    def __sig__(self) -> bytes:
        # return the RFC 3279 encoding:
        return utils.encode_dss_signature(self.r, self.s)

    def from_signer(self, sig: bytes) -> None:
        # set up from the RFC 3279 encoding:
        (r, s) = utils.decode_dss_signature(sig)
        self.r = MPI(r)
        self.s = MPI(s)

    def parse(self, packet: bytearray) -> None:
        self.r = MPI(packet)
        self.s = MPI(packet)


class ECDSASignature(DSASignature):
    pass


class EdDSASignature(DSASignature):
    def from_signer(self, sig):
        lsig = len(sig)
        if lsig % 2 != 0:
            raise PGPError("malformed EdDSA signature")
        split = lsig // 2
        self.r = MPI(self.bytes_to_int(sig[:split]))
        self.s = MPI(self.bytes_to_int(sig[split:]))

    def __sig__(self):
        # TODO: change this length when EdDSA can be used with another curve (Ed448)
        siglen = (EllipticCurveOID.Ed25519.key_size + 7) // 8
        return self.int_to_bytes(self.r, siglen) + self.int_to_bytes(self.s, siglen)


class NativeEdDSASignature(Signature):
    @abc.abstractproperty
    def __siglen__(self) -> int:
        'the size of this native EdDSA signature object'

    def __bytearray__(self) -> bytearray:
        return bytearray(self._rawsig)

    def from_signer(self, sig: bytes) -> None:
        if len(sig) != self.__siglen__:
            raise ValueError(f'{self!r} must be {self.__siglen__} bytes long, not {len(sig)}')
        self._rawsig = sig

    def __sig__(self) -> bytes:
        return self._rawsig

    def __copy__(self) -> NativeEdDSASignature:
        sig = self.__class__()
        sig._rawsig = self._rawsig
        return sig

    def parse(self, packet: bytearray) -> None:
        self._rawsig = bytes(packet[:self.__siglen__])
        del packet[:self.__siglen__]


class Ed25519Signature(NativeEdDSASignature):
    @property
    def __siglen__(self) -> int:
        return 64


class Ed448Signature(NativeEdDSASignature):
    @property
    def __siglen__(self) -> int:
        return 114


class PubKey(MPIs):
    __pubfields__: Tuple = ()
    __pubkey_algo__: Optional[PubKeyAlgorithm] = None

    @property
    def __mpis__(self):
        yield from self.__pubfields__

    def __init__(self) -> None:
        super().__init__()
        for field in self.__pubfields__:
            if isinstance(field, tuple):  # pragma: no cover
                field, val = field
            else:
                val = MPI(0)
            setattr(self, field, val)

    @abc.abstractmethod
    def __pubkey__(self):
        """return the requisite *PublicKey class from the cryptography library"""

    def __len__(self) -> int:
        return sum(len(getattr(self, i)) for i in self.__pubfields__)

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        for field in self.__pubfields__:
            _bytes += getattr(self, field).to_mpibytes()

        return _bytes

    def publen(self) -> int:
        return len(self)

    def verify(self, subj, sigbytes, hash_alg):
        raise NotImplementedError()  # pragma: no cover

    def encrypt(self, symalg: Optional[SymmetricKeyAlgorithm], data: bytes, fpr: Fingerprint) -> CipherText:
        raise NotImplementedError()

    def _encrypt_helper(self, symalg: Optional[SymmetricKeyAlgorithm], plaintext: bytes) -> bytes:
        'Common code for re-shaping session keys before storing in PKESK'
        checksum = self.int_to_bytes(sum(plaintext) % 65536, 2)
        if symalg is not None:
            plaintext = bytes([symalg]) + plaintext
        return plaintext + checksum


class OpaquePubKey(PubKey):  # pragma: no cover
    def __init__(self):
        super().__init__()
        self.data = bytearray()

    def __iter__(self):
        yield self.data

    def __pubkey__(self):
        raise NotImplementedError()

    def __bytearray__(self) -> bytearray:
        return self.data

    def parse(self, packet: bytearray) -> None:
        ##TODO: this needs to be length-bounded to the end of the packet
        self.data = packet


class RSAPub(PubKey):
    __pubfields__ = ('n', 'e')
    __pubkey_algo__ = PubKeyAlgorithm.RSAEncryptOrSign

    def __pubkey__(self) -> rsa.RSAPublicKey:
        return rsa.RSAPublicNumbers(self.e, self.n).public_key()

    def verify(self, subj, sigbytes, hash_alg):
        # zero-pad sigbytes if necessary
        sigbytes = (b'\x00' * (self.n.byte_length() - len(sigbytes))) + sigbytes
        try:
            self.__pubkey__().verify(sigbytes, subj, padding.PKCS1v15(), hash_alg)
        except InvalidSignature:
            return False
        return True

    def encrypt(self, symalg: Optional[SymmetricKeyAlgorithm], data: bytes, fpr: Fingerprint) -> RSACipherText:
        ct = RSACipherText()
        ct.from_raw_bytes(self.__pubkey__().encrypt(self._encrypt_helper(symalg, data), padding.PKCS1v15()))
        return ct

    def parse(self, packet: bytearray) -> None:
        self.n = MPI(packet)
        self.e = MPI(packet)


class DSAPub(PubKey):
    __pubfields__ = ('p', 'q', 'g', 'y')
    __pubkey_algo__ = PubKeyAlgorithm.DSA

    def __pubkey__(self):
        params = dsa.DSAParameterNumbers(self.p, self.q, self.g)
        return dsa.DSAPublicNumbers(self.y, params).public_key()

    def verify(self, subj, sigbytes, hash_alg):
        try:
            self.__pubkey__().verify(sigbytes, subj, hash_alg)
        except InvalidSignature:
            return False
        return True

    def parse(self, packet: bytearray) -> None:
        self.p = MPI(packet)
        self.q = MPI(packet)
        self.g = MPI(packet)
        self.y = MPI(packet)


class ElGPub(PubKey):
    __pubfields__ = ('p', 'g', 'y')
    __pubkey_algo__ = PubKeyAlgorithm.ElGamal

    def __pubkey__(self):
        raise NotImplementedError()

    def parse(self, packet: bytearray) -> None:
        self.p = MPI(packet)
        self.g = MPI(packet)
        self.y = MPI(packet)


class ECPoint:
    def __init__(self, packet=None):
        if packet is None:
            return
        xy = bytearray(MPI(packet).to_mpibytes()[2:])
        self.format = ECPointFormat(xy[0])
        del xy[0]
        if self.format == ECPointFormat.Standard:
            xylen = len(xy)
            if xylen % 2 != 0:
                raise PGPError("malformed EC point")
            self.bytelen = xylen // 2
            self.x = MPI(MPIs.bytes_to_int(xy[:self.bytelen]))
            self.y = MPI(MPIs.bytes_to_int(xy[self.bytelen:]))
        elif self.format == ECPointFormat.Native:
            self.bytelen = 0  # dummy value for copy
            self.x = bytes(xy)
            self.y = None
        else:
            raise NotImplementedError("No curve is supposed to use only X or Y coordinates")

    @classmethod
    def from_values(cls, bitlen, pform, x, y=None):
        ct = cls()
        ct.bytelen = (bitlen + 7) // 8
        ct.format = pform
        ct.x = x
        ct.y = y
        return ct

    def __len__(self) -> int:
        """ Returns length of MPI encoded point """
        if self.format == ECPointFormat.Standard:
            return 2 * self.bytelen + 3
        elif self.format == ECPointFormat.Native:
            return len(self.x) + 3
        else:
            raise NotImplementedError("No curve is supposed to use only X or Y coordinates")

    def to_mpibytes(self) -> bytes:
        """ Returns MPI encoded point as it should be written in packet """
        b = bytearray()
        b.append(self.format)
        if self.format == ECPointFormat.Standard:
            b += MPIs.int_to_bytes(self.x, self.bytelen)
            b += MPIs.int_to_bytes(self.y, self.bytelen)
        elif self.format == ECPointFormat.Native:
            b += self.x
        else:
            raise NotImplementedError("No curve is supposed to use only X or Y coordinates")
        return MPI(MPIs.bytes_to_int(b)).to_mpibytes()

    def __bytearray__(self) -> bytearray:
        return bytearray(self.to_mpibytes())

    def __copy__(self) -> ECPoint:
        pk = self.__class__()
        pk.bytelen = self.bytelen
        pk.format = self.format
        pk.x = copy.copy(self.x)
        pk.y = copy.copy(self.y)
        return pk


class ECDSAPub(PubKey):
    __pubfields__ = ('p',)
    __pubkey_algo__ = PubKeyAlgorithm.ECDSA

    def __init__(self) -> None:
        super().__init__()
        self.oid: Union[bytes, EllipticCurveOID] = EllipticCurveOID.NIST_P256

    def __len__(self) -> int:
        return len(self.p) + len(self.oid)

    def __pubkey__(self):
        return ec.EllipticCurvePublicNumbers(self.p.x, self.p.y, self.oid.curve()).public_key()

    def __bytearray__(self) -> bytearray:
        _b = bytearray()
        _b += bytes(self.oid)
        _b += self.p.to_mpibytes()
        return _b

    def __copy__(self) -> ECDSAPub:
        pkt = super().__copy__()
        if not isinstance(pkt, ECDSAPub):
            raise TypeError(f"Failed to create ECDSAPub when copying, got {type(pkt)}")
        pkt.oid = self.oid
        return pkt

    def verify(self, subj, sigbytes, hash_alg):
        try:
            self.__pubkey__().verify(sigbytes, subj, ec.ECDSA(hash_alg))
        except InvalidSignature:
            return False
        return True

    def parse(self, packet: bytearray) -> None:
        self.oid = EllipticCurveOID.parse(packet)

        if isinstance(self.oid, EllipticCurveOID):
            self.p: Union[ECPoint, MPI] = ECPoint(packet)
            if self.p.format != ECPointFormat.Standard:
                raise PGPIncompatibleECPointFormatError("Only Standard format is valid for ECDSA")
        else:
            self.p = MPI(packet)


class EdDSAPub(PubKey):
    __pubfields__ = ('p', )
    __pubkey_algo__ = PubKeyAlgorithm.EdDSA

    def __init__(self) -> None:
        super().__init__()
        self.oid: Union[bytes, EllipticCurveOID] = EllipticCurveOID.Ed25519

    def __len__(self) -> int:
        return len(self.p) + len(self.oid)

    def __bytearray__(self) -> bytearray:
        _b = bytearray()
        _b += bytes(self.oid)
        _b += self.p.to_mpibytes()
        return _b

    def __pubkey__(self):
        return ed25519.Ed25519PublicKey.from_public_bytes(self.p.x)

    def __copy__(self) -> EdDSAPub:
        pkt = super().__copy__()
        if not isinstance(pkt, EdDSAPub):
            raise TypeError(f"Failed to create EdDSAPub when copying, got {type(pkt)}")
        pkt.oid = self.oid
        return pkt

    def verify(self, subj, sigbytes, hash_alg):
        # GnuPG requires a pre-hashing with EdDSA
        # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-06#section-14.8
        digest = hashes.Hash(hash_alg)
        digest.update(subj)
        subj = digest.finalize()
        try:
            self.__pubkey__().verify(sigbytes, subj)
        except InvalidSignature:
            return False
        return True

    def parse(self, packet: bytearray) -> None:
        self.oid = EllipticCurveOID.parse(packet)

        if isinstance(self.oid, EllipticCurveOID):
            self.p: Union[ECPoint, MPI] = ECPoint(packet)
            if self.p.format != ECPointFormat.Native:
                raise PGPIncompatibleECPointFormatError("Only Native format is valid for EdDSA")
        else:
            self.p = MPI(packet)


NativeEdDSAPrivType = Union[ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey]
NativeEdDSAPubType = Union[ed25519.Ed25519PublicKey, ed448.Ed448PublicKey]


class NativeEdDSAPub(PubKey):
    @abc.abstractproperty
    def _public_length(self) -> int:
        'the size of this native EdDSA public key object'
    @abc.abstractmethod
    def pub_from_bytes(self, b: bytes) -> NativeEdDSAPubType:
        ''''derive a public key from bytes'''

    def __pubkey__(self) -> NativeEdDSAPubType:
        return self._raw_pubkey

    def __bytearray__(self) -> bytearray:
        return bytearray(self._raw_pubkey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def parse(self, packet: bytearray) -> None:
        self._raw_pubkey = self.pub_from_bytes(bytes(packet[:self._public_length]))
        del packet[:self._public_length]

    def verify(self, subj: bytes, sigbytes: bytes, hash_alg: cryptography_HashAlgorithm) -> bool:
        hasher = hashes.Hash(hash_alg)
        hasher.update(subj)
        subj = hasher.finalize()
        try:
            self._raw_pubkey.verify(sigbytes, subj)
        except InvalidSignature:
            return False
        return True

    def __len__(self) -> int:
        return self._public_length


class Ed25519Pub(NativeEdDSAPub):
    __pubkey_algo__ = PubKeyAlgorithm.Ed25519

    @property
    def _public_length(self) -> int:
        return 32

    def pub_from_bytes(self, b: bytes) -> ed25519.Ed25519PublicKey:
        return ed25519.Ed25519PublicKey.from_public_bytes(b)


class Ed448Pub(NativeEdDSAPub):
    __pubkey_algo__ = PubKeyAlgorithm.Ed448

    @property
    def _public_length(self) -> int:
        return 56

    def pub_from_bytes(self, b: bytes) -> ed448.Ed448PublicKey:
        return ed448.Ed448PublicKey.from_public_bytes(b)


class ECDHPub(PubKey):
    __pubfields__ = ('p',)
    __pubkey_algo__ = PubKeyAlgorithm.ECDH

    def __init__(self) -> None:
        super().__init__()
        self.oid: Union[bytes, EllipticCurveOID] = EllipticCurveOID.NIST_P256
        self.kdf = ECKDF()

    def __len__(self):
        return len(self.p) + len(self.kdf) + len(self.oid)

    def __pubkey__(self):
        if self.oid is EllipticCurveOID.Curve25519:
            return x25519.X25519PublicKey.from_public_bytes(self.p.x)
        else:
            return ec.EllipticCurvePublicNumbers(self.p.x, self.p.y, self.oid.curve()).public_key()

    def __bytearray__(self) -> bytearray:
        _b = bytearray()
        _b += bytes(self.oid)
        _b += self.p.to_mpibytes()
        _b += self.kdf.__bytearray__()
        return _b

    def __copy__(self) -> ECDHPub:
        pkt = super().__copy__()
        if not isinstance(pkt, ECDHPub):
            raise TypeError(f"Failed to create ECDHAPub when copying, got {type(pkt)}")
        pkt.oid = self.oid
        pkt.kdf = copy.copy(self.kdf)
        return pkt

    def parse(self, packet: bytearray) -> None:
        """
        Algorithm-Specific Fields for ECDH keys:

          o  a variable-length field containing a curve OID, formatted
             as follows:

             -  a one-octet size of the following field; values 0 and
                0xFF are reserved for future extensions

             -  the octets representing a curve OID, defined in
                Section 11

             -  MPI of an EC point representing a public key

          o  a variable-length field containing KDF parameters,
             formatted as follows:

             -  a one-octet size of the following fields; values 0 and
                0xff are reserved for future extensions

             -  a one-octet value 01, reserved for future extensions

             -  a one-octet hash function ID used with a KDF

             -  a one-octet algorithm ID for the symmetric algorithm
                used to wrap the symmetric key used for the message
                encryption; see Section 8 for details
        """
        self.oid = EllipticCurveOID.parse(packet)

        if isinstance(self.oid, EllipticCurveOID):
            self.p: Union[ECPoint, MPI] = ECPoint(packet)
            if self.oid is EllipticCurveOID.Curve25519:
                if self.p.format != ECPointFormat.Native:
                    raise PGPIncompatibleECPointFormatError("Only Native format is valid for Curve25519")
            elif self.p.format != ECPointFormat.Standard:
                raise PGPIncompatibleECPointFormatError("Only Standard format is valid for this curve")
        else:
            self.p = MPI(packet)

        self.kdf.parse(packet)

    def encrypt(self, symalg: Optional[SymmetricKeyAlgorithm], data: bytes, fpr: Fingerprint) -> ECDHCipherText:
        """
        For convenience, the synopsis of the encoding method is given below;
        however, this section, [NIST-SP800-56A], and [RFC3394] are the
        normative sources of the definition.

            Obtain the authenticated recipient public key R
            Generate an ephemeral key pair {v, V=vG}
            Compute the shared point S = vR;
            m = symm_alg_ID || session key || checksum || pkcs5_padding;
            curve_OID_len = (byte)len(curve_OID);
            Param = curve_OID_len || curve_OID || public_key_alg_ID || 03
            || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap || "Anonymous
            Sender    " || recipient_fingerprint;
            Z_len = the key size for the KEK_alg_ID used with AESKeyWrap
            Compute Z = KDF( S, Z_len, Param );
            Compute C = AESKeyWrap( Z, m ) as per [RFC3394]
            VB = convert point V to the octet string
            Output (MPI(VB) || len(C) || C).

        The decryption is the inverse of the method given.  Note that the
        recipient obtains the shared secret by calculating
        """
        if not isinstance(self.oid, EllipticCurveOID):
            raise NotImplementedError(f"cannot encrypt to unknown curve ({self.oid!r})")
        # m may need to be PKCS5-padded
        padder = PKCS7(64).padder()
        m = padder.update(self._encrypt_helper(symalg, data)) + padder.finalize()

        ct = ECDHCipherText()

        # generate ephemeral key pair and keep public key in ct
        # use private key to compute the shared point "s"
        if self.oid is EllipticCurveOID.Curve25519:
            vx25519 = x25519.X25519PrivateKey.generate()
            xcoord = vx25519.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                       format=serialization.PublicFormat.Raw)
            ct.p = ECPoint.from_values(self.oid.key_size, ECPointFormat.Native, xcoord)
            s = vx25519.exchange(self.__pubkey__())
        else:
            vecdh = ec.generate_private_key(self.oid.curve())
            x = MPI(vecdh.public_key().public_numbers().x)
            y = MPI(vecdh.public_key().public_numbers().y)
            ct.p = ECPoint.from_values(self.oid.key_size, ECPointFormat.Standard, x, y)
            s = vecdh.exchange(ec.ECDH(), self.__pubkey__())

        # derive the wrapping key
        z = self.kdf.derive_key(s, self.oid, PubKeyAlgorithm.ECDH, fpr)

        # compute C
        ct.c = bytearray(aes_key_wrap(z, m))

        return ct


class NativeCFRGXPub(PubKey):
    @abc.abstractproperty
    def _public_length(self) -> int:
        'the size of this native CFRG X* public key object'
    @abc.abstractproperty
    def _native_type(self) -> Union[Type[x25519.X25519PublicKey], Type[x448.X448PublicKey]]:
        'what is the native type to use?'

    def exchange(self,
                 priv: Union[x25519.X25519PrivateKey, x448.X448PrivateKey],
                 pub: Union[x25519.X25519PublicKey, x448.X448PublicKey]) -> bytes:
        if isinstance(pub, x25519.X25519PublicKey) and isinstance(priv, x25519.X25519PrivateKey):
            return priv.exchange(pub)
        if isinstance(pub, x448.X448PublicKey) and isinstance(priv, x448.X448PrivateKey):
            return priv.exchange(pub)
        raise TypeError(f"{type(self)}: mismatched public key {type(pub)} and private key {type(priv)}")

    def __pubkey__(self) -> Union[x25519.X25519PublicKey, x448.X448PublicKey]:
        return self._raw_pubkey

    @abc.abstractmethod
    def new_ciphertext(self) -> NativeCFRGXCipherText:
        'generate a new ciphertext'

    def __bytearray__(self) -> bytearray:
        return bytearray(self._raw_pubkey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def parse(self, packet: bytearray) -> None:
        self._raw_pubkey = self._native_type.from_public_bytes(bytes(packet[:self._public_length]))
        del packet[:self._public_length]

    def __len__(self) -> int:
        return self._public_length

    def encrypt(self, symalg: Optional[SymmetricKeyAlgorithm], data: bytes, fpr: Fingerprint) -> NativeCFRGXCipherText:
        ct = self.new_ciphertext()
        ephemeral_key = ct.gen_priv()
        ct._sym_algo = symalg

        shared_secret: bytes = self.exchange(ephemeral_key, self._raw_pubkey)
        hkdf = HKDF(algorithm=ct.kdf_hash_algo(), length=ct.aes_keywrap_keylen, salt=None, info=ct.hkdf_info)
        mykey_bytes = self._raw_pubkey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if ct._ephemeral is None:
            raise TypeError("CipherText ephemeral value is missing")
        ephemeral_bytes = ct._ephemeral.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key_wrap_key: bytes = hkdf.derive(ephemeral_bytes + mykey_bytes + shared_secret)

        ct._text = aes_key_wrap(key_wrap_key, data)
        return ct


class X25519Pub(NativeCFRGXPub):
    __pubkey_algo__ = PubKeyAlgorithm.X25519

    @property
    def _public_length(self) -> int:
        return 32

    @property
    def _native_type(self) -> Union[Type[x25519.X25519PublicKey], Type[x448.X448PublicKey]]:
        return x25519.X25519PublicKey

    def new_ciphertext(self) -> X25519CipherText:
        return X25519CipherText()


class X448Pub(NativeCFRGXPub):
    __pubkey_algo__ = PubKeyAlgorithm.X448

    @property
    def _public_length(self) -> int:
        return 56

    @property
    def _native_type(self) -> Union[Type[x25519.X25519PublicKey], Type[x448.X448PublicKey]]:
        return x448.X448PublicKey

    def new_ciphertext(self) -> X448CipherText:
        return X448CipherText()


class S2KSpecifier(Field):
    """
    This is just the S2K specifier and its various options
    This is useful because it works in SKESK objects directly.

    In the context of a Secret Key protection, you need more than just
    this: instead, look into the String2Key object.

    3.7.  String-to-Key (S2K) Specifiers

    String-to-key (S2K) specifiers are used to convert passphrase strings
    into symmetric-key encryption/decryption keys.  They are used in two
    places, currently: to encrypt the secret part of private keys in the
    private keyring, and to convert passphrases to encryption keys for
    symmetrically encrypted messages.

    3.7.1.  String-to-Key (S2K) Specifier Types

    There are three types of S2K specifiers currently supported, and
    some reserved values:

       ID          S2K Type
       --          --------
       0           Simple S2K
       1           Salted S2K
       2           Reserved value
       3           Iterated and Salted S2K
       100 to 110  Private/Experimental S2K

    These are described in Sections 3.7.1.1 - 3.7.1.3.

    3.7.1.1.  Simple S2K

    This directly hashes the string to produce the key data.  See below
    for how this hashing is done.

       Octet 0:        0x00
       Octet 1:        hash algorithm

    Simple S2K hashes the passphrase to produce the session key.  The
    manner in which this is done depends on the size of the session key
    (which will depend on the cipher used) and the size of the hash
    algorithm's output.  If the hash size is greater than the session key
    size, the high-order (leftmost) octets of the hash are used as the
    key.

    If the hash size is less than the key size, multiple instances of the
    hash context are created -- enough to produce the required key data.
    These instances are preloaded with 0, 1, 2, ... octets of zeros (that
    is to say, the first instance has no preloading, the second gets
    preloaded with 1 octet of zero, the third is preloaded with two
    octets of zeros, and so forth).

    As the data is hashed, it is given independently to each hash
    context.  Since the contexts have been initialized differently, they
    will each produce different hash output.  Once the passphrase is
    hashed, the output data from the multiple hashes is concatenated,
    first hash leftmost, to produce the key data, with any excess octets
    on the right discarded.

    3.7.1.2.  Salted S2K

    This includes a "salt" value in the S2K specifier -- some arbitrary
    data -- that gets hashed along with the passphrase string, to help
    prevent dictionary attacks.

       Octet 0:        0x01
       Octet 1:        hash algorithm
       Octets 2-9:     8-octet salt value

    Salted S2K is exactly like Simple S2K, except that the input to the
    hash function(s) consists of the 8 octets of salt from the S2K
    specifier, followed by the passphrase.

    3.7.1.3.  Iterated and Salted S2K

    This includes both a salt and an octet count.  The salt is combined
    with the passphrase and the resulting value is hashed repeatedly.
    This further increases the amount of work an attacker must do to try
    dictionary attacks.

       Octet  0:        0x03
       Octet  1:        hash algorithm
       Octets 2-9:      8-octet salt value
       Octet  10:       count, a one-octet, coded value

    The count is coded into a one-octet number using the following
    formula:

       #define EXPBIAS 6
           count = ((Int32)16 + (c & 15)) << ((c >> 4) + EXPBIAS);

    The above formula is in C, where "Int32" is a type for a 32-bit
    integer, and the variable "c" is the coded count, Octet 10.

    Iterated-Salted S2K hashes the passphrase and salt data multiple
    times.  The total number of octets to be hashed is specified in the
    encoded count in the S2K specifier.  Note that the resulting count
    value is an octet count of how many octets will be hashed, not an
    iteration count.

    Initially, one or more hash contexts are set up as with the other S2K
    algorithms, depending on how many octets of key data are needed.
    Then the salt, followed by the passphrase data, is repeatedly hashed
    until the number of octets specified by the octet count has been
    hashed.  The one exception is that if the octet count is less than
    the size of the salt plus passphrase, the full salt plus passphrase
    will be hashed even though that is greater than the octet count.
    After the hashing is done, the data is unloaded from the hash
    context(s) as with the other S2K algorithms.
    """

    def __init__(self,
                 s2ktype: String2KeyType = String2KeyType.Iterated,
                 halg: HashAlgorithm = HashAlgorithm.SHA256,
                 salt: Optional[bytes] = None,
                 iteration_count: int = 65011712,  # default to maximum iterations
                 gnupg_extension: S2KGNUExtension = S2KGNUExtension.NoSecret,
                 smartcard_serial: Optional[bytes] = None,
                 argon2_time: int = 1,
                 argon2_parallelism: int = 4,
                 argon2_memory_exp: int = 21,
                 ):
        if salt is not None:
            if s2ktype.salt_length == 0:
                raise ValueError(f"No salt for S2KSpecifier type {s2ktype!r}")
            elif len(salt) != s2ktype.salt_length:
                raise ValueError(f"S2KSpecifier salt for {s2ktype!r} must be {s2ktype.salt_length} octets, not {len(salt)}")
        if smartcard_serial is not None:
            if s2ktype != String2KeyType.GNUExtension:
                raise ValueError(f"Smartcard serial number should only be specfied for GNUExtension S2KSpecifier, not {s2ktype!r}")
            if gnupg_extension != S2KGNUExtension.Smartcard:
                raise ValueError(f"Smartcard serial number should only be specified with S2KGNUExtension Smartcard, not {gnupg_extension!r}")
            if len(smartcard_serial) > 16:
                raise ValueError(f"Smartcard serial number should be 16 octets or less, not {len(smartcard_serial)}")
        if s2ktype is String2KeyType.Argon2:
            if argon2_time < 1 or argon2_time > 255:
                raise ValueError(f"Argon2 time parameter must be between 1 and 255, inclusive, not {argon2_time}")
            if argon2_parallelism < 1 or argon2_parallelism > 255:
                raise ValueError(f"Argon2 parallelism parameter must be between 1 and 255, inclusive, not {argon2_time}")
            if argon2_memory_exp > 255:
                raise ValueError(f"Argon2 memory size exponent (2^m KiB) must be at most 255, not m={argon2_memory_exp}")
            if (1 << argon2_memory_exp) < 8 * argon2_parallelism:
                raise ValueError(
                    f"Argon2 memory size in KiB (m={argon2_memory_exp}, or {1 << argon2_memory_exp}KiB) should be at least parallelism({argon2_parallelism})*8")
        super().__init__()
        self._type: String2KeyType = s2ktype
        self._halg: HashAlgorithm = halg
        self._salt: Optional[bytes] = None
        if salt is not None:
            self._salt = bytes(salt)
        self._count = 65011712  # the default!
        if s2ktype is String2KeyType.Iterated:
            self.iteration_count = iteration_count
        self._a2_t = argon2_time
        self._a2_p = argon2_parallelism
        self._a2_m = argon2_memory_exp
        self._gnupg_extension: S2KGNUExtension = gnupg_extension
        self._smartcard_serial: Optional[bytes] = None
        if smartcard_serial is not None:
            self.smartcard_serial = bytes(smartcard_serial)

    def __copy__(self) -> S2KSpecifier:
        s2k = S2KSpecifier()
        s2k._type = self._type
        if self._type is String2KeyType.Unknown:
            s2k._opaque_type = self._opaque_type

        s2k._halg = self._halg
        s2k._salt = copy.copy(self._salt)
        s2k._count = self._count
        s2k._gnupg_extension = self._gnupg_extension
        s2k._smartcard_serial = copy.copy(self._smartcard_serial)
        s2k._a2_t = self._a2_t
        s2k._a2_p = self._a2_p
        s2k._a2_m = self._a2_m
        return s2k

    @sdproperty
    def iteration_count(self) -> int:
        if self._type is None:
            raise ValueError(f"Cannot retrieve iteration count when S2KSpecifier type is unset")
        if self._type is not String2KeyType.Iterated:
            raise ValueError(f"Cannot retrieve iteration count on S2KSpecifier Type {self._type!r}")
        if self._count is None:
            raise ValueError(f"S2KSpecifier iteration count is unset")
        return self._count

    @staticmethod
    def _convert_iteration_count_to_byte(count: int) -> bytes:
        if count < 1:
            raise ValueError("Cannot set S2K iteration count below 1")
        exponent: int = min(21, max(6, math.floor(math.log2(count)) - 4))
        mantissa: int = min(31, max(16, count >> exponent))
        val = (mantissa - 16) | ((exponent - 6) << 4)
        return bytes([val])

    @staticmethod
    def _convert_iteration_byte_to_count(octet: Union[bytes, bytearray]) -> int:
        if len(octet) != 1:
            raise ValueError("expected a single byte")
        mantissa: int = (octet[0] & 0x0f) + 16
        exponent: int = (octet[0] >> 4) + 6
        return mantissa << exponent

    @iteration_count.register
    def iteration_count_int(self, val: int) -> None:
        if self._type is not String2KeyType.Iterated:
            raise ValueError(f"Cannot set iteration count on S2KSpecifier type {self._type!r}")
        f = self._convert_iteration_byte_to_count(self._convert_iteration_count_to_byte(val))
        if f != val:
            warn(f"Could not select S2K iteration count {val}, using {f} instead")
        self._count = f

    @iteration_count.register
    def iteration_count_octet(self, val: Union[bytes, bytearray]) -> None:
        self._count = self._convert_iteration_byte_to_count(val)

    @sdproperty
    def iteration_octet(self) -> Optional[bytes]:
        if self._type is not String2KeyType.Iterated or self._count is None:
            return None
        return self._convert_iteration_count_to_byte(self._count)

    @sdproperty
    def halg(self) -> HashAlgorithm:
        return self._halg

    @halg.register
    def halg_set(self, val: Union[HashAlgorithm, int]) -> None:
        self._halg = HashAlgorithm(val)

    @sdproperty
    def salt(self) -> bytes:
        if self._type.salt_length == 0:
            return b''
        if self._salt is None:
            self._salt = os.urandom(self._type.salt_length)
        return self._salt

    @salt.register
    def salt_bytes(self, val: Union[bytes, bytearray]) -> None:
        if self._type.salt_length == 0:
            raise ValueError(f"salt cannnot be set for String2KeyType {self._type!r}")
        if len(val) != self._type.salt_length:
            raise ValueError(f"salt for String2KeyType {self._type!r} should be {self._type.salt_length}, not {len(val)}")
        self._salt = bytes(val)

    @property
    def gnuext(self) -> Optional[S2KGNUExtension]:
        return self._gnupg_extension

    @sdproperty
    def smartcard_serial(self) -> Optional[bytes]:
        if self._type is not String2KeyType.GNUExtension or self._gnupg_extension is not S2KGNUExtension.Smartcard:
            return None
        return self._smartcard_serial

    @smartcard_serial.register
    def smartcard_serial_bytes(self, val: Union[bytes, bytearray]) -> None:
        if self._type is not String2KeyType.GNUExtension:
            raise ValueError(f"smartcard serial number can only be set for String2KeyType GNUExtension, not {self._type!r}")
        if self._gnupg_extension != S2KGNUExtension.Smartcard:
            raise ValueError(f"smartcard serial number can only be set when S2KGNUExtension is Smartcard, not {self._gnupg_extension!r}")
        if len(val) > 16:
            raise ValueError(f"smartcard serial number can only be 16 octets maximum, not {len(val)}")
        self._smartcard_serial = bytes(val)

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        if self._type is String2KeyType.Unknown:
            _bytes.append(self._opaque_type)
        else:
            _bytes.append(self._type)
        if self._type is String2KeyType.GNUExtension:
            return self._gnu_bytearray(_bytes)
        if self._type in {String2KeyType.Simple, String2KeyType.Salted, String2KeyType.Iterated}:
            _bytes.append(self._halg)
        _bytes += self.salt
        if self._type is String2KeyType.Iterated:
            _bytes += self.iteration_octet
        if self._type is String2KeyType.Argon2:
            _bytes.append(self._a2_t)
            _bytes.append(self._a2_p)
            _bytes.append(self._a2_m)
        return _bytes

    def __len__(self) -> int:
        return len(self.__bytearray__())

    def parse(self, packet: bytearray) -> None:
        self._type = String2KeyType(packet[0])
        if self._type is String2KeyType.Unknown:
            self._opaque_type: int = packet[0]
        del packet[0]

        if self._type is String2KeyType.GNUExtension:
            return self._parse_gnu_extension(packet)

        if self._type in {String2KeyType.Simple, String2KeyType.Salted, String2KeyType.Iterated}:
            self._halg = HashAlgorithm(packet[0])
            del packet[0]

        if self._type.salt_length > 0:
            self._salt = bytes(packet[:self._type.salt_length])
            del packet[:self._type.salt_length]

        if self._type is String2KeyType.Iterated:
            self.iteration_count = packet[:1]
            del packet[:1]

        if self._type is String2KeyType.Argon2:
            (self._a2_t, self._a2_p, self._a2_m) = packet[:3]
            del packet[:3]

    def _gnu_bytearray(self, _bytes):
        if self._type is not String2KeyType.GNUExtension:
            raise ValueError(f"This is not a GnuPG-extended S2K specifier ({self._type})")
        if self._gnupg_extension is None:
            raise ValueError(f"S2KGNUExtension is unset")
        _bytes += b'\x00GNU'
        _bytes.append(self._gnupg_extension)
        if self._gnupg_extension == S2KGNUExtension.Smartcard:
            if self._smartcard_serial is None:
                _bytes.append(0)
            else:
                _bytes.append(len(self._smartcard_serial))
                _bytes += self._smartcard_serial
        return _bytes

    def _parse_gnu_extension(self, packet) -> None:
        """
        https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=doc/DETAILS;h=3046523da62c576cf6a765a8b0829876cfdc6b3b;hb=b0f0791e4ade845b2a0e2a94dbda4f3bf1ceb039#l1346

        GNU extensions to the S2K algorithm

        1 octet  - S2K Specifier: 101
        4 octets - "\x00GNU"
        1 octet  - GNU S2K Extension Number.

        If such a GNU extension is used neither an IV nor any kind of
        checksum is used.  The defined GNU S2K Extension Numbers are:

        - 1 :: Do not store the secret part at all.  No specific data
               follows.

        - 2 :: A stub to access smartcards.  This data follows:
               - One octet with the length of the following serial number.
               - The serial number. Regardless of what the length octet
                 indicates no more than 16 octets are stored.
        """
        if self._type != String2KeyType.GNUExtension:
            raise ValueError(f"This is not a GnuPG-extended S2K specifier ({self._type!r})")
        if packet[:4] != b'\x00GNU':
            raise PGPError("Invalid S2K GNU extension magic value")
        del packet[:4]

        self._gnupg_extension = S2KGNUExtension(packet[0])
        del packet[0]

        if self._gnupg_extension == S2KGNUExtension.Smartcard:
            slen = min(packet[0], 16)
            del packet[0]
            self.smartcard_serial = packet[:slen]
            del packet[:slen]

    def derive_key(self, passphrase: Union[str, bytes], keylen_bits: int) -> bytes:
        if self._type not in {String2KeyType.Simple, String2KeyType.Salted, String2KeyType.Iterated, String2KeyType.Argon2}:
            raise NotImplementedError(f"Cannot derive key from S2KSpecifier {self._type!r}")

        if not isinstance(passphrase, bytes):
            passphrase = passphrase.encode('utf-8')

        if self._type is String2KeyType.Argon2:
            return hash_secret_raw(passphrase, self.salt, self._a2_t, 1 << self._a2_m, self._a2_p, keylen_bits // 8, ArgonType.ID, 0x13)

        hashlen = self._halg.digest_size * 8

        ctx = int(math.ceil((keylen_bits / hashlen)))

        base_count = len(self.salt + passphrase)
        count = base_count
        if self._type is String2KeyType.Iterated and self._count > count:
            count = self._count

        hcount = (count // base_count)
        hleft = count - (hcount * base_count)

        h = []
        for i in range(0, ctx):
            _h = self._halg.hasher
            _h.update(b'\x00' * i + (self.salt + passphrase) * hcount + (self.salt + passphrase)[:hleft])
            h.append(_h)

        # and return the key!
        return b''.join(hc.finalize() for hc in h)[:(keylen_bits // 8)]


class String2Key(Field):
    """
    Used for secret key protection.
    This contains an S2KUsage flag.  Depending on the S2KUsage flag, it can also contain an S2KSpecifier, an encryption algorithm, an AEAD mode, and an IV.
    """

    @sdproperty
    def encalg(self) -> SymmetricKeyAlgorithm:
        return self._encalg

    @encalg.register
    def encalg_int(self, val: int) -> None:
        if isinstance(val, SymmetricKeyAlgorithm):
            self._encalg: SymmetricKeyAlgorithm = val
        else:
            self._encalg = SymmetricKeyAlgorithm(val)

    @property
    def _iv_length(self) -> int:
        if self.usage is S2KUsage.Unprotected:
            return 0
        elif self.usage in {S2KUsage.MalleableCFB, S2KUsage.CFB}:
            if not self._specifier._type.has_iv:
                # this is likely some sort of weird extension case
                return 0
            return self.encalg.block_size // 8
        elif self.usage is S2KUsage.AEAD:
            if self._aead_mode is None:
                raise TypeError("missing AEAD mode for String2Key with AEAD usage")
            return self._aead_mode.iv_len
        else:
            return SymmetricKeyAlgorithm(self.usage).block_size // 8

    def gen_iv(self) -> None:
        ivlen = self._iv_length
        if self._iv is None and ivlen:
            self._iv: Optional[bytes] = os.urandom(ivlen)

    @sdproperty
    def iv(self) -> Optional[bytes]:
        ivlen = self._iv_length
        if ivlen == 0:
            return None
        return self._iv

    @iv.register
    def iv_bytearray(self, val: Optional[Union[bytearray, bytes]]) -> None:
        ivlen = self._iv_length
        if ivlen == 0:
            if val is not None and len(val) > 0:
                raise PGPError(f"setting an IV of length {len(val)} when it should be nothing")
            self._iv = None
        else:
            if val is not None:
                if len(val) != ivlen:
                    raise PGPError(f"setting an IV of length {len(val)} when it should be {ivlen}")
                val = bytes(val)
            self._iv = val

    def __init__(self, key_version: int) -> None:
        super().__init__()
        self.key_version = key_version
        self.usage = S2KUsage.Unprotected
        self._encalg = SymmetricKeyAlgorithm.AES256
        self._aead_mode: Optional[AEADMode] = None
        self._specifier = S2KSpecifier()
        self._iv = None

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes.append(self.usage)
        if bool(self):
            conditionals = bytearray()
            conditionals.append(self.encalg)
            if self.usage is S2KUsage.AEAD:
                if self._aead_mode is None:
                    raise TypeError("AEAD Mode was not set")
                conditionals.append(self._aead_mode)
            s2kbytes = self._specifier.__bytearray__()
            if self.key_version == 6 and self.usage in {S2KUsage.MalleableCFB, S2KUsage.CFB, S2KUsage.AEAD}:
                conditionals.append(len(s2kbytes))
            conditionals += s2kbytes
            if self.iv is not None:
                conditionals += self.iv
            if self.key_version == 6:
                _bytes.append(len(conditionals))
            _bytes += conditionals
        return _bytes

    def __len__(self) -> int:
        return len(self.__bytearray__())

    def __bool__(self) -> bool:
        # FIXME: what if usage octet is a cipher algorithm?  This is
        # deprecated enough that it must not be generated, but we
        # might want to handle it properly on decryption
        return self.usage in {S2KUsage.AEAD, S2KUsage.CFB, S2KUsage.MalleableCFB}

    def __copy__(self) -> String2Key:
        s2k = String2Key(self.key_version)
        s2k.usage = self.usage
        s2k.encalg = self.encalg
        s2k._specifier = copy.copy(self._specifier)

        s2k.iv = self.iv
        return s2k

    def parse(self, packet: bytearray) -> None:
        self.usage = S2KUsage(packet[0])
        del packet[0]

        if bool(self):
            if self.key_version == 6:
                paramlen = packet[0]
                del packet[0]

            self.encalg = SymmetricKeyAlgorithm(packet[0])
            del packet[0]

            if self.usage is S2KUsage.AEAD:
                self._aead_mode = AEADMode(packet[0])
                del packet[0]

            if self.key_version == 6:
                speclen = packet[0]
                del packet[0]

            self._specifier.parse(packet)
            if self.encalg is not SymmetricKeyAlgorithm.Plaintext:
                ivlen = self._iv_length
                if ivlen:
                    self.iv = packet[:(ivlen)]
                    del packet[:(ivlen)]

    def derive_key(self, passphrase) -> bytes:
        derivable = {S2KUsage.MalleableCFB, S2KUsage.CFB, S2KUsage.AEAD}
        if self.usage not in derivable:
            raise ValueError(f"can only derive key from String2Key object when usage octet is {derivable}, not {self.usage}")
        if self.encalg is None:
            raise ValueError("cannot derive key from String2Key object when encalg is unset")
        return self._specifier.derive_key(passphrase, self.encalg.key_size)


class ECKDF(Field):
    """
    o  a variable-length field containing KDF parameters,
       formatted as follows:

       -  a one-octet size of the following fields; values 0 and
          0xff are reserved for future extensions

       -  a one-octet value 01, reserved for future extensions

       -  a one-octet hash function ID used with a KDF

       -  a one-octet algorithm ID for the symmetric algorithm
          used to wrap the symmetric key used for the message
          encryption; see Section 8 for details
    """
    @sdproperty
    def halg(self):
        return self._halg

    @halg.register(int)
    @halg.register(HashAlgorithm)
    def halg_int(self, val):
        self._halg = HashAlgorithm(val)

    @sdproperty
    def encalg(self):
        return self._encalg

    @encalg.register(int)
    @encalg.register(SymmetricKeyAlgorithm)
    def encalg_int(self, val):
        self._encalg = SymmetricKeyAlgorithm(val)

    def __init__(self):
        super().__init__()
        self.halg = 0
        self.encalg = 0

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes.append(len(self) - 1)
        _bytes.append(0x01)
        _bytes.append(self.halg)
        _bytes.append(self.encalg)
        return _bytes

    def __len__(self):
        return 4

    def parse(self, packet: bytearray) -> None:
        # packet[0] should always be 3
        # packet[1] should always be 1
        # TODO: this assert is likely not necessary, but we should raise some kind of exception
        #       if parsing fails due to these fields being incorrect
        assert packet[:2] == b'\x03\x01'
        del packet[:2]

        self.halg = packet[0]
        del packet[0]

        self.encalg = packet[0]
        del packet[0]

    def derive_key(self, s: bytes, curve: EllipticCurveOID, pkalg: PubKeyAlgorithm, fingerprint: Fingerprint) -> bytes:
        # wrapper around the Concatenation KDF method provided by cryptography
        # assemble the additional data as defined in RFC 6637:
        #  Param = curve_OID_len || curve_OID || public_key_alg_ID || 03 || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap || "Anonymous
        data = bytearray()
        data += bytes(curve)
        data.append(pkalg)
        data += b'\x03\x01'
        data.append(self.halg)
        data.append(self.encalg)
        data += b'Anonymous Sender    '
        data += binascii.unhexlify(fingerprint.replace(' ', ''))

        ckdf = ConcatKDFHash(algorithm=getattr(hashes, self.halg.name)(), length=self.encalg.key_size // 8, otherinfo=bytes(data))
        return ckdf.derive(s)


class PrivKey(PubKey):
    __privfields__: Tuple = ()

    @property
    def __mpis__(self):
        yield from super().__mpis__
        yield from self.__privfields__

    def __init__(self, key_version: int = 4) -> None:
        super().__init__()

        self.key_version = key_version
        self.s2k = String2Key(key_version)
        self.encbytes = bytearray()
        self.chksum = bytearray()

        for field in self.__privfields__:
            setattr(self, field, MPI(0))

    def _append_private_fields(self, _bytes: bytearray) -> None:
        '''override this function if the private fields are not MPIs'''
        for field in self.__privfields__:
            _bytes += getattr(self, field).to_mpibytes()

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes += super().__bytearray__()

        _bytes += self.s2k.__bytearray__()
        if self.s2k:
            _bytes += self.encbytes

        else:
            self._append_private_fields(_bytes)

        if self.s2k.usage is S2KUsage.Unprotected and self.key_version == 4:  # checksum is only appropriate for v4 keys:
            _bytes += self.chksum

        return _bytes

    def __len__(self):
        nbytes = super().__len__() + len(self.s2k) + len(self.chksum)
        if self.s2k:
            nbytes += len(self.encbytes)

        else:
            nbytes += sum(len(getattr(self, i)) for i in self.__privfields__)

        return nbytes

    def __copy__(self):
        pk = super().__copy__()
        pk.key_version = self.key_version
        pk.s2k = copy.copy(self.s2k)
        pk.encbytes = copy.copy(self.encbytes)
        pk.chksum = copy.copy(self.chksum)
        return pk

    @abc.abstractmethod
    def __privkey__(self):
        """return the requisite *PrivateKey class from the cryptography library"""

    @abc.abstractmethod
    def _generate(self, key_size_or_oid: Optional[Union[int, EllipticCurveOID]]) -> None:
        """Generate a new PrivKey"""

    def _compute_chksum(self):
        "Calculate the key checksum"

    def publen(self) -> int:
        return super().__len__()

    def _aead_object_and_ad(self, passphrase: Union[str, bytes],
                            packet_type: PacketType,
                            creation_time: datetime) -> Tuple[AEAD, bytes]:
        if self.__pubkey_algo__ is None:
            raise ValueError(f"S2K Usage Octet indicates AEAD, but the public key algorithm of this secret key is unknown ({type(self)})")
        if self.s2k._aead_mode is None:
            raise ValueError(f"S2K Usage Octet indicates AEAD, but no AEAD mode set")
        # The info parameter is comprised of the Packet Tag in OpenPGP format encoding (bits 7 and 6 set, bits 5-0 carry the packet tag), the packet version, and the cipher-algo and AEAD-mode used to encrypt the key material.
        hkdf_info = bytes([0xc0 | int(packet_type), self.key_version, int(self.s2k.encalg), int(self.s2k._aead_mode)])
        hkdf = HKDF(algorithm=SHA256(), length=self.s2k.encalg.key_size // 8, salt=None, info=hkdf_info)
        aeadkey: bytes = hkdf.derive(self.s2k.derive_key(passphrase))
        aead = AEAD(self.s2k.encalg, self.s2k._aead_mode, aeadkey)

        # As additional data, the Packet Tag in OpenPGP format encoding (bits 7 and 6 set, bits 5-0 carry the packet tag), followed by the public key packet fields, starting with the packet version number, are passed to the AEAD algorithm.
        # For example, the additional data used with a Secret-Key Packet of version 4 consists of the octets 0xC5, 0x04, followed by four octets of creation time, one octet denoting the public-key algorithm, and the algorithm-specific public-key parameters.
        # For a Secret-Subkey Packet, the first octet would be 0xC7.
        # For a version 6 key packet, the second octet would be 0x06, and the four-octet octet count of the public key material would be included as well (see {{public-key-packet-formats}}).
        associated_data = bytes([0xc0 | int(packet_type), self.key_version])
        associated_data += self.int_to_bytes(int(creation_time.timestamp()), 4)
        associated_data += bytes([int(self.__pubkey_algo__)])
        pubkey_data = bytes(super().__bytearray__())
        associated_data += self.int_to_bytes(len(pubkey_data), 4)
        associated_data += pubkey_data
        return (aead, associated_data)

    def encrypt_keyblob(self, passphrase: str,
                        enc_alg: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES256,
                        hash_alg: Optional[HashAlgorithm] = None,
                        s2kspec: Optional[S2KSpecifier] = None,
                        iv: Optional[bytes] = None,
                        aead_mode: Optional[AEADMode] = None,
                        packet_type: PacketType = PacketType.SecretKey,
                        creation_time: Optional[datetime] = None) -> None:
        if aead_mode is not None:
            self.s2k.usage = S2KUsage.AEAD
            self.s2k._aead_mode = aead_mode
        else:
            self.s2k.usage = S2KUsage.CFB
        self.s2k.encalg = enc_alg
        passed_s2kspec: bool
        if s2kspec is not None:
            passed_s2kspec = True
        else:
            passed_s2kspec = False
            s2kspec = S2KSpecifier()
        if iv is not None:
            self.s2k.iv = iv
        if hash_alg is not None:
            if hash_alg != s2kspec.halg:
                if passed_s2kspec:
                    warn(f"Passed S2K specifier with hash algorithm {s2kspec.halg!r} but also passed hash algorithm {hash_alg!r}, going with {hash_alg!r}")
                s2kspec.halg = hash_alg
        self.s2k._specifier = copy.copy(s2kspec)
        self.s2k.gen_iv()

        pt = bytearray()
        self._append_private_fields(pt)

        if self.s2k.usage is S2KUsage.CFB:
            # append a SHA-1 hash of the plaintext so far to the plaintext
            pt += HashAlgorithm.SHA1.digest(pt)

            sessionkey = self.s2k.derive_key(passphrase)
            del passphrase

            # encrypt
            self.encbytes = bytearray(_cfb_encrypt(bytes(pt), bytes(sessionkey), enc_alg, bytes(self.s2k.iv)))
        elif self.s2k.usage is S2KUsage.AEAD:
            if creation_time is None:
                raise ValueError("S2K Usage Octet indicates AEAD, but no creation time provided")
            if aead_mode is None:
                if self.s2k._aead_mode is None:
                    raise ValueError("S2K Usage Octet indicates AEAD, but no AEAD mode provided")
                else:
                    aead_mode = self.s2k._aead_mode
            else:
                if self.s2k._aead_mode is None:
                    self.s2k._aead_mode = aead_mode
                else:
                    if aead_mode is not self.s2k._aead_mode:
                        raise ValueError(f"Conflicting String2Key AEAD Modes: {aead_mode}, {self.s2k._aead_mode}")

            (aead, associated_data) = self._aead_object_and_ad(passphrase, packet_type, creation_time)
            self.encbytes = bytearray(aead.encrypt(bytes(self.s2k.iv), bytes(pt), associated_data))
        else:
            raise PGPError(f"Unknown S2K usage octet {self.s2k.usage!r}, expected {S2KUsage.AEAD!r} or {S2KUsage.CFB!r}")

        # delete pt and clear self
        del pt
        self.clear()

    @abc.abstractmethod
    def decrypt_keyblob(self, passphrase: Union[str, bytes]) -> None:
        raise NotImplementedError()

    def _decrypt_keyblob_helper(self, passphrase: Union[str, bytes]) -> Optional[bytearray]:
        if not self.s2k:  # pragma: no cover
            # not encrypted
            return None

        # Encryption/decryption of the secret data is done in CFB mode using
        # the key created from the passphrase and the Initial Vector from the
        # packet.  A different mode is used with V3 keys (which are only RSA)
        # than with other key formats.  (...)
        #
        # With V4 keys, a simpler method is used.  All secret MPI values are
        # encrypted in CFB mode, including the MPI bitcount prefix.

        # derive the session key from our passphrase, and then unreference passphrase
        sessionkey = self.s2k.derive_key(passphrase)
        del passphrase

        # attempt to decrypt this key
        pt = _cfb_decrypt(bytes(self.encbytes), bytes(sessionkey), self.s2k.encalg, bytes(self.s2k.iv))

        # check the hash to see if we decrypted successfully or not
        if self.s2k.usage is S2KUsage.CFB and not pt[-20:] == HashAlgorithm.SHA1.digest(pt[:-20]):
            # if the usage byte is 254, key material is followed by a 20-octet sha-1 hash of the rest
            # of the key material block
            raise PGPDecryptionError("Passphrase was incorrect!")

        if self.s2k.usage is S2KUsage.MalleableCFB and not self.bytes_to_int(pt[-2:]) == (sum(bytearray(pt[:-2])) % 65536):  # pragma: no cover
            # if the usage byte is 255, key material is followed by a 2-octet checksum of the rest
            # of the key material block
            raise PGPDecryptionError("Passphrase was incorrect!")

        return bytearray(pt)

    def sign(self, sigdata, hash_alg):
        raise NotImplementedError()  # pragma: no cover

    def decrypt(self, ct: CipherText, fpr: Fingerprint, get_symalg: bool) -> Tuple[Optional[SymmetricKeyAlgorithm], bytes]:
        raise NotImplementedError()

    def _decrypt_helper(self, plaintext: bytes, get_symalg: bool) -> Tuple[Optional[SymmetricKeyAlgorithm], bytes]:
        """
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
        """

        m = bytearray(plaintext)

        symalg: Optional[SymmetricKeyAlgorithm] = None
        keysize = len(m) - 2
        if get_symalg:
            symalg = SymmetricKeyAlgorithm(m[0])
            del m[0]
            keysize = symalg.key_size // 8

        symkey = m[:keysize]
        del m[:keysize]

        checksum = self.bytes_to_int(m[:2])
        del m[:2]

        if sum(symkey) % 65536 != checksum:  # pragma: no cover
            raise PGPDecryptionError(f"{self.__pubkey_algo__!r} decryption failed (sum: {sum(symkey)}, stored: {checksum}, length: {len(m)})")
        if len(m) > 0:
            raise PGPDecryptionError(f"{len(m)} bytes left unconsumed during {self.__pubkey_algo__!r} decryption")

        return (symalg, symkey)

    def clear(self) -> None:
        """delete and re-initialize all private components to zero"""
        for field in self.__privfields__:
            delattr(self, field)
            setattr(self, field, MPI(0))


class OpaquePrivKey(PrivKey, OpaquePubKey):  # pragma: no cover
    def __privkey__(self):
        raise NotImplementedError()

    def _generate(self, key_size_or_oid: Optional[Union[int, EllipticCurveOID]]) -> None:
        raise NotImplementedError()

    def decrypt_keyblob(self, passphrase: Union[str, bytes]) -> None:
        raise NotImplementedError()


class RSAPriv(PrivKey, RSAPub):
    __privfields__ = ('d', 'p', 'q', 'u')

    def __privkey__(self):
        return rsa.RSAPrivateNumbers(self.p, self.q, self.d,
                                     rsa.rsa_crt_dmp1(self.d, self.p),
                                     rsa.rsa_crt_dmq1(self.d, self.q),
                                     rsa.rsa_crt_iqmp(self.p, self.q),
                                     rsa.RSAPublicNumbers(self.e, self.n)).private_key()

    def _compute_chksum(self):
        chs = sum(sum(bytearray(c.to_mpibytes())) for c in (self.d, self.p, self.q, self.u)) % 65536
        self.chksum = bytearray(self.int_to_bytes(chs, 2))

    def _generate(self, key_size: Optional[Union[int, EllipticCurveOID]]) -> None:
        if any(c != 0 for c in self):  # pragma: no cover
            raise PGPError("key is already populated")

        if key_size is None:  # choose a default RSA key size for the user
            key_size = 3072

        if not isinstance(key_size, int):
            raise PGPError(f"Did not understand RSA key size {key_size}")

        # generate some big numbers!
        pk = rsa.generate_private_key(65537, key_size)
        pkn = pk.private_numbers()

        self.n = MPI(pkn.public_numbers.n)
        self.e = MPI(pkn.public_numbers.e)
        self.d = MPI(pkn.d)
        self.p = MPI(pkn.p)
        self.q = MPI(pkn.q)
        # from the RFC:
        # "- MPI of u, the multiplicative inverse of p, mod q."
        # or, simply, p^-1 mod p
        # rsa.rsa_crt_iqmp(p, q) normally computes q^-1 mod p,
        # so if we swap the values around we get the answer we want
        self.u = MPI(rsa.rsa_crt_iqmp(pkn.q, pkn.p))

        del pkn
        del pk

        self._compute_chksum()

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.d = MPI(packet)
            self.p = MPI(packet)
            self.q = MPI(packet)
            self.u = MPI(packet)

            if self.s2k.usage is S2KUsage.Unprotected:
                self.chksum = packet[:2]
                del packet[:2]

        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

    def decrypt_keyblob(self, passphrase: Union[str, bytes]) -> None:
        kb = self._decrypt_keyblob_helper(passphrase)
        del passphrase
        if kb is None:
            return

        self.d = MPI(kb)
        self.p = MPI(kb)
        self.q = MPI(kb)
        self.u = MPI(kb)

        if self.s2k.usage in {S2KUsage.CFB, S2KUsage.MalleableCFB}:
            self.chksum = kb
            del kb

    def sign(self, sigdata: bytes, hash_alg: HashAlgorithm) -> bytes:
        return self.__privkey__().sign(sigdata, padding.PKCS1v15(), hash_alg)

    def decrypt(self, ct: CipherText, fpr: Fingerprint, get_symalg: bool) -> Tuple[Optional[SymmetricKeyAlgorithm], bytes]:
        if not isinstance(ct, RSACipherText):
            raise TypeError(f"RSAPriv: cannot decrypt {type(ct)}")

        # pad up ct with null bytes if necessary
        ciphertext = ct.me_mod_n.to_mpibytes()[2:]
        ciphertext = b'\x00' * ((self.__privkey__().key_size // 8) - len(ciphertext)) + ciphertext

        return self._decrypt_helper(self.__privkey__().decrypt(ciphertext, padding.PKCS1v15()), True)


class DSAPriv(PrivKey, DSAPub):
    __privfields__ = ('x',)

    def __privkey__(self):
        params = dsa.DSAParameterNumbers(self.p, self.q, self.g)
        pn = dsa.DSAPublicNumbers(self.y, params)
        return dsa.DSAPrivateNumbers(self.x, pn).private_key()

    def _compute_chksum(self):
        chs = sum(bytearray(self.x.to_mpibytes())) % 65536
        self.chksum = bytearray(self.int_to_bytes(chs, 2))

    def _generate(self, key_size: Optional[Union[int, EllipticCurveOID]]) -> None:
        if any(c != 0 for c in self):  # pragma: no cover
            raise PGPError("key is already populated")

        if key_size is None:  # choose a default DSA key size for the user
            key_size = 3072

        if not isinstance(key_size, int):
            raise PGPError(f"Did not understand DSA key size {key_size}")

        # generate some big numbers!
        pk = dsa.generate_private_key(key_size)
        pkn = pk.private_numbers()

        self.p = MPI(pkn.public_numbers.parameter_numbers.p)
        self.q = MPI(pkn.public_numbers.parameter_numbers.q)
        self.g = MPI(pkn.public_numbers.parameter_numbers.g)
        self.y = MPI(pkn.public_numbers.y)
        self.x = MPI(pkn.x)

        del pkn
        del pk

        self._compute_chksum()

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.x = MPI(packet)

        else:
            self.encbytes = packet

        if self.s2k.usage in {S2KUsage.Unprotected, S2KUsage.MalleableCFB}:
            self.chksum = packet[:2]
            del packet[:2]

    def decrypt_keyblob(self, passphrase: Union[str, bytes]) -> None:
        kb = self._decrypt_keyblob_helper(passphrase)
        del passphrase
        if kb is None:
            return

        self.x = MPI(kb)

        if self.s2k.usage in {S2KUsage.CFB, S2KUsage.MalleableCFB}:
            self.chksum = kb
            del kb

    def sign(self, sigdata, hash_alg):
        return self.__privkey__().sign(sigdata, hash_alg)


class ElGPriv(PrivKey, ElGPub):
    __privfields__ = ('x', )

    def __privkey__(self):
        raise NotImplementedError()

    def _compute_chksum(self):
        chs = sum(bytearray(self.x.to_mpibytes())) % 65536
        self.chksum = bytearray(self.int_to_bytes(chs, 2))

    def _generate(self, key_size_or_oid: Optional[Union[int, EllipticCurveOID]]) -> None:
        raise NotImplementedError(PubKeyAlgorithm.ElGamal)

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.x = MPI(packet)

        else:
            self.encbytes = packet

        if self.s2k.usage in {S2KUsage.Unprotected, S2KUsage.MalleableCFB}:
            self.chksum = packet[:2]
            del packet[:2]

    def decrypt_keyblob(self, passphrase: Union[str, bytes]) -> None:
        kb = self._decrypt_keyblob_helper(passphrase)
        del passphrase
        if kb is None:
            return

        self.x = MPI(kb)

        if self.s2k.usage in [S2KUsage.CFB, S2KUsage.MalleableCFB]:
            self.chksum = kb
            del kb


class ECDSAPriv(PrivKey, ECDSAPub):
    __privfields__ = ('s', )

    def __privkey__(self):
        ecp = ec.EllipticCurvePublicNumbers(self.p.x, self.p.y, self.oid.curve())
        return ec.EllipticCurvePrivateNumbers(self.s, ecp).private_key()

    def _compute_chksum(self) -> None:
        chs = sum(bytearray(self.s.to_mpibytes())) % 65536
        self.chksum = bytearray(self.int_to_bytes(chs, 2))

    def _generate(self, params: Optional[Union[int, EllipticCurveOID]]) -> None:
        if any(c != 0 for c in self):  # pragma: no cover
            raise PGPError("Key is already populated!")

        if params is None:
            # select a default ECDSA elliptic curve for the user:
            self.oid = EllipticCurveOID.NIST_P256
        elif isinstance(params, int):
            oid = EllipticCurveOID.from_key_size(params)
            if oid is None:
                raise ValueError("No supported Elliptic Curve of size {params}")
            self.oid = oid
        else:
            self.oid = params

        pk = ec.generate_private_key(self.oid.curve())
        pubn = pk.public_key().public_numbers()
        self.p = ECPoint.from_values(self.oid.key_size, ECPointFormat.Standard, MPI(pubn.x), MPI(pubn.y))
        self.s = MPI(pk.private_numbers().private_value)
        self._compute_chksum()

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.s = MPI(packet)

            if self.s2k.usage is S2KUsage.Unprotected:
                self.chksum = packet[:2]
                del packet[:2]
        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

    def decrypt_keyblob(self, passphrase: Union[str, bytes]) -> None:
        kb = self._decrypt_keyblob_helper(passphrase)
        del passphrase
        if kb is None:
            return
        self.s = MPI(kb)

    def sign(self, sigdata, hash_alg):
        return self.__privkey__().sign(sigdata, ec.ECDSA(hash_alg))


class EdDSAPriv(PrivKey, EdDSAPub):
    __privfields__ = ('s', )

    def __privkey__(self):
        s = self.int_to_bytes(self.s, (self.oid.key_size + 7) // 8)
        return ed25519.Ed25519PrivateKey.from_private_bytes(s)

    def _compute_chksum(self):
        chs = sum(bytearray(self.s.to_mpibytes())) % 65536
        self.chksum = bytearray(self.int_to_bytes(chs, 2))

    def _generate(self, params: Optional[Union[int, EllipticCurveOID]]) -> None:
        if any(c != 0 for c in self):  # pragma: no cover
            raise PGPError("Key is already populated!")

        if params is None:
            self.oid = EllipticCurveOID.Ed25519
        elif isinstance(params, int):
            oid = EllipticCurveOID.from_key_size(params)
            if oid is None:
                raise ValueError("No supported Elliptic Curve of size {params}")
            self.oid = oid
        else:
            self.oid = params

        if self.oid is not EllipticCurveOID.Ed25519:
            raise ValueError(f"EdDSA only supported with {EllipticCurveOID.Ed25519}, not {self.oid}")

        pk = ed25519.Ed25519PrivateKey.generate()
        x = pk.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        self.p = ECPoint.from_values(self.oid.key_size, ECPointFormat.Native, x)
        self.s = MPI(self.bytes_to_int(pk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )))
        self._compute_chksum()

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.s = MPI(packet)
            if self.s2k.usage is S2KUsage.Unprotected:
                self.chksum = packet[:2]
                del packet[:2]
        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

    def decrypt_keyblob(self, passphrase: Union[str, bytes]) -> None:
        kb = self._decrypt_keyblob_helper(passphrase)
        del passphrase
        if kb is None:
            return
        self.s = MPI(kb)

    def sign(self, sigdata, hash_alg):
        # GnuPG requires a pre-hashing with EdDSA
        # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-06#section-14.8
        digest = hashes.Hash(hash_alg)
        digest.update(sigdata)
        sigdata = digest.finalize()
        return self.__privkey__().sign(sigdata)


class NativeEdDSAPriv(PrivKey, NativeEdDSAPub):
    @abc.abstractproperty
    def _private_length(self) -> int:
        'the length in bytes of the native private key object'
    @abc.abstractmethod
    def gen_priv(self) -> NativeEdDSAPrivType:
        'generate a new secret key'
    @abc.abstractmethod
    def priv_from_bytes(self, b: bytes) -> NativeEdDSAPrivType:
        'load a private key from native bytes representation'

    def sign(self, sigdata: bytes, hash_alg: cryptography_HashAlgorithm) -> bytes:
        hasher = hashes.Hash(hash_alg)
        hasher.update(sigdata)
        sigdata = hasher.finalize()
        return self._raw_privkey.sign(sigdata)

    def _compute_chksum(self):
        b = bytearray()
        self._append_private_fields(b)
        chs = sum(b) % 65536
        self.chksum = bytearray(self.int_to_bytes(chs, 2))

    def clear(self) -> None:
        if hasattr(self, '_raw_privkey'):
            delattr(self, '_raw_privkey')

    def _generate(self, keysize: Optional[Union[int, EllipticCurveOID]] = None) -> None:
        if keysize is not None:
            raise ValueError("Native EdDSA keys should always receive a None parameter for the keysize, as they are fixed size")
        self._raw_privkey = self.gen_priv()
        self._raw_pubkey = self._raw_privkey.public_key()
        self._compute_chksum()

    def __privkey__(self):
        return self._raw_privkey

    def _append_private_fields(self, _bytes: bytearray) -> None:
        _bytes += self._raw_privkey.private_bytes(encoding=serialization.Encoding.Raw,
                                                  format=serialization.PrivateFormat.Raw,
                                                  encryption_algorithm=serialization.NoEncryption())

    def parse(self, packet: bytearray) -> None:
        NativeEdDSAPub.parse(self, packet)
        # parse s2k business
        self.s2k.parse(packet)

        if not self.s2k:
            self._raw_privkey = self.priv_from_bytes(packet[:self._private_length])
            del packet[:self._private_length]
        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

    def decrypt_keyblob(self, passphrase: Union[str, bytes]) -> None:
        kb = super().decrypt_keyblob(passphrase)
        del passphrase

        self._raw_privkey = self.priv_from_bytes(kb[:self._private_length])
        del kb[:self._private_length]

        if self.s2k.usage in {S2KUsage.MalleableCFB, S2KUsage.CFB}:
            self.chksum = kb
            del kb


class Ed25519Priv(NativeEdDSAPriv, Ed25519Pub):
    @property
    def _private_length(self) -> int:
        return 32

    def gen_priv(self) -> ed25519.Ed25519PrivateKey:
        return ed25519.Ed25519PrivateKey.generate()

    def priv_from_bytes(self, b: bytes) -> ed25519.Ed25519PrivateKey:
        return ed25519.Ed25519PrivateKey.from_private_bytes(b)


class Ed448Priv(NativeEdDSAPriv, Ed448Pub):
    @property
    def _private_length(self) -> int:
        return 57

    def gen_priv(self) -> ed448.Ed448PrivateKey:
        return ed448.Ed448PrivateKey.generate()

    def priv_from_bytes(self, b: bytes) -> ed448.Ed448PrivateKey:
        return ed448.Ed448PrivateKey.from_private_bytes(b)


class ECDHPriv(ECDSAPriv, ECDHPub):  # type: ignore[misc] # (definition of __copy__ in base classes ECDHPub and ECDSAPub differs)
    def __bytearray__(self) -> bytearray:
        _b = ECDHPub.__bytearray__(self)
        _b += self.s2k.__bytearray__()
        if not self.s2k:
            _b += self.s.to_mpibytes()
            if self.s2k.usage is S2KUsage.Unprotected:
                _b += self.chksum
        else:
            _b += self.encbytes
        return _b

    def __len__(self) -> int:
        nbytes = ECDHPub.__len__(self) + len(self.s2k) + len(self.chksum)
        if self.s2k:
            nbytes += len(self.encbytes)
        else:
            nbytes += sum(len(getattr(self, i)) for i in self.__privfields__)
        return nbytes

    def __privkey__(self):
        if self.oid is EllipticCurveOID.Curve25519:
            # NOTE: openssl and GPG don't use the same endianness for Curve25519 secret value
            s = self.int_to_bytes(self.s, (self.oid.key_size + 7) // 8, 'little')
            return x25519.X25519PrivateKey.from_private_bytes(s)
        else:
            return ECDSAPriv.__privkey__(self)

    def _generate(self, params: Optional[Union[int, EllipticCurveOID]]) -> None:
        if params is None:  # choose a default curve for the ECDH user
            _oid: Optional[EllipticCurveOID] = EllipticCurveOID.Curve25519
        elif isinstance(params, int):
            _oid = EllipticCurveOID.from_key_size(params)
            if _oid is None:
                raise ValueError("No supported Elliptic Curve of size {params}")
        else:
            _oid = params

        if _oid is EllipticCurveOID.Curve25519:
            if any(c != 0 for c in self):  # pragma: no cover
                raise PGPError("Key is already populated!")
            self.oid = _oid
            pk = x25519.X25519PrivateKey.generate()
            x = pk.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            self.p = ECPoint.from_values(self.oid.key_size, ECPointFormat.Native, x)
            # NOTE: openssl and GPG don't use the same endianness for Curve25519 secret value
            self.s = MPI(self.bytes_to_int(pk.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ), 'little'))
            self._compute_chksum()
        else:
            ECDSAPriv._generate(self, _oid)
        if isinstance(self.oid, EllipticCurveOID):
            self.kdf.halg = self.oid.kdf_halg
            self.kdf.encalg = self.oid.kek_alg

    def publen(self):
        return ECDHPub.__len__(self)

    def parse(self, packet: bytearray) -> None:
        ECDHPub.parse(self, packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.s = MPI(packet)
            if self.s2k.usage is S2KUsage.Unprotected:
                self.chksum = packet[:2]
                del packet[:2]
        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

    def sign(self, sigdata, hash_alg):
        raise PGPError("Cannot sign with an ECDH key")

    def decrypt(self, ct: CipherText, fpr: Fingerprint, get_symalg: bool) -> Tuple[Optional[SymmetricKeyAlgorithm], bytes]:
        if not isinstance(ct, ECDHCipherText):
            raise TypeError(f"ECDHPriv: cannot decrypt {type(ct)}")

        if not isinstance(self.oid, EllipticCurveOID):
            raise TypeError(f"ECDH: Cannot decrypt with unknown curve({self.oid!r})")

        if self.oid is EllipticCurveOID.Curve25519:
            vx25519 = x25519.X25519PublicKey.from_public_bytes(ct.p.x)
            s = self.__privkey__().exchange(vx25519)
        else:
            # assemble the public component of ephemeral key v
            vecdh = ec.EllipticCurvePublicNumbers(ct.p.x, ct.p.y, self.oid.curve()).public_key()
            # compute s using the inverse of how it was derived during encryption
            s = self.__privkey__().exchange(ec.ECDH(), vecdh)

        # derive the wrapping key
        z = self.kdf.derive_key(s, self.oid, PubKeyAlgorithm.ECDH, fpr)

        # unwrap and unpad m
        _m = aes_key_unwrap(z, ct.c)

        padder = PKCS7(64).unpadder()
        return self._decrypt_helper(padder.update(_m) + padder.finalize(), get_symalg)


class NativeCFRGXPriv(PrivKey, NativeCFRGXPub):
    def __privkey__(self) -> Union[x25519.X25519PrivateKey, x448.X448PrivateKey]:
        return self._raw_privkey

    def clear(self) -> None:
        if hasattr(self, '_raw_privkey'):
            delattr(self, '_raw_privkey')

    @abc.abstractproperty
    def _private_length(self) -> int:
        'the length in byes of the native private key object'
    @abc.abstractproperty
    def _native_private_type(self) -> Union[Type[x25519.X25519PrivateKey], Type[x448.X448PrivateKey]]:
        'the native object type from the cryptography library'

    def _compute_chksum(self):
        b = bytearray()
        self._append_private_fields(b)
        chs = sum(b) % 65536
        self.chksum = bytearray(self.int_to_bytes(chs, 2))

    def _generate(self, keysize: Optional[Union[int, EllipticCurveOID]] = None) -> None:
        if keysize is not None:
            raise ValueError("Native CFRG key exchange ('X*') keys should always receive a None parameter for keysize, as they are fixed length")
        self._raw_privkey = self._native_private_type.generate()
        self._raw_pubkey = self._raw_privkey.public_key()
        self._compute_chksum()

    def parse(self, packet: bytearray) -> None:
        NativeCFRGXPub.parse(self, packet)
        # parse s2k business
        self.s2k.parse(packet)

        if not self.s2k:
            self._raw_privkey = self._native_private_type.from_private_bytes(packet[:self._private_length])
            del packet[:self._private_length]
        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

    def _append_private_fields(self, _bytes: bytearray) -> None:
        _bytes += self._raw_privkey.private_bytes(encoding=serialization.Encoding.Raw,
                                                  format=serialization.PrivateFormat.Raw,
                                                  encryption_algorithm=serialization.NoEncryption())

    def sign(self, sigdata: bytes, hash_alg: HashAlgorithm) -> bytes:
        raise PGPError("Cannot sign with a CFRG X* key")

    def decrypt_keyblob(self, passphrase):
        kb = super().decrypt_keyblob(passphrase)
        del passphrase

        self._raw_privkey = self._native_private_type.from_private_bytes(kb[:self._private_length])
        del kb[:self._private_length]

        if self.s2k.usage in [254, 255]:
            self.chksum = kb
            del kb

    def decrypt(self, ct: CipherText, fpr: Fingerprint, get_symalg: bool) -> Tuple[Optional[SymmetricKeyAlgorithm], bytes]:
        if not isinstance(ct, NativeCFRGXCipherText):
            raise TypeError(f"Cannot decrypt {type(ct)}, expected NativeCFRGXCipherText")
        if ct._ephemeral is None or ct._text is None:
            raise PGPDecryptionError(f"Cannot decrypt uninitialized {type(ct)}")

        if ct._sym_algo is None and get_symalg:
            raise TypeError("Asked for symmetric algorithm but none was present")

        shared_secret: bytes = self.exchange(self.__privkey__(), ct._ephemeral)
        hkdf = HKDF(algorithm=ct.kdf_hash_algo(), length=ct.aes_keywrap_keylen, salt=None, info=ct.hkdf_info)
        mykey_bytes = self.__privkey__().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ephemeral_bytes = ct._ephemeral.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key_wrap_key: bytes = hkdf.derive(ephemeral_bytes + mykey_bytes + shared_secret)
        cleartext = aes_key_unwrap(key_wrap_key, ct._text)

        return (ct._sym_algo, cleartext)


class X25519Priv(NativeCFRGXPriv, X25519Pub):
    @property
    def _private_length(self) -> int:
        return 32

    @property
    def _native_private_type(self) -> Union[Type[x25519.X25519PrivateKey], Type[x448.X448PrivateKey]]:
        return x25519.X25519PrivateKey


class X448Priv(NativeCFRGXPriv, X448Pub):
    @property
    def _private_length(self) -> int:
        return 56

    @property
    def _native_private_type(self) -> Union[Type[x25519.X25519PrivateKey], Type[x448.X448PrivateKey]]:
        return x448.X448PrivateKey


class CipherText(MPIs):
    def __init__(self) -> None:
        super().__init__()
        for i in self.__mpis__:
            setattr(self, i, MPI(0))

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        for i in self:
            _bytes += i.to_mpibytes()
        return _bytes


class RSACipherText(CipherText):
    __mpis__ = ('me_mod_n', )

    def from_raw_bytes(self, packet: bytes) -> None:
        self.me_mod_n = MPI(self.bytes_to_int(packet))

    def parse(self, packet: bytearray) -> None:
        self.me_mod_n = MPI(packet)


class ElGCipherText(CipherText):
    __mpis__ = ('gk_mod_p', 'myk_mod_p')

    def parse(self, packet: bytearray) -> None:
        self.gk_mod_p = MPI(packet)
        self.myk_mod_p = MPI(packet)


class ECDHCipherText(CipherText):
    __mpis__ = ('p',)

    def __init__(self) -> None:
        super().__init__()
        self.c = bytearray(0)

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes += self.p.to_mpibytes()
        _bytes.append(len(self.c))
        _bytes += self.c
        return _bytes

    def parse(self, packet: bytearray) -> None:
        # read ephemeral public key
        self.p = ECPoint(packet)
        # read signature value
        clen = packet[0]
        del packet[0]
        self.c += packet[:clen]
        del packet[:clen]


NativeCFRGXPrivType = Union[x25519.X25519PrivateKey, x448.X448PrivateKey]
NativeCFRGXPubType = Union[x25519.X25519PublicKey, x448.X448PublicKey]


class NativeCFRGXCipherText(CipherText):
    @abc.abstractproperty
    def public_bytes(self) -> int:
        '''size of public key (in bytes)'''
    @abc.abstractproperty
    def aes_keywrap_keylen(self) -> int:
        '''size of AES key (bytes)'''
    @abc.abstractproperty
    def hkdf_info(self) -> bytes:
        '''the prefix string for key derivation'''
    @abc.abstractmethod
    def gen_priv(self) -> NativeCFRGXPrivType:
        '''generate a private key, setting the internal ephemeral'''
    @abc.abstractmethod
    def pub_from_bytes(self, b: bytes) -> NativeCFRGXPubType:
        '''derive a public key from bytes'''
    @abc.abstractmethod
    def kdf_hash_algo(self) -> cryptography_HashAlgorithm:
        '''generate a new hash algorithm for use with HKDF'''

    def __init__(self) -> None:
        self._text: Optional[bytes] = None
        self._sym_algo: Optional[SymmetricKeyAlgorithm] = None
        self._ephemeral: Optional[NativeCFRGXPubType] = None

    def __bytearray__(self) -> bytearray:
        if self._ephemeral is None:
            raise ValueError(f"ephemeral value for {type(self)} is not initialized, cannot produce wire format")
        if self._text is None:
            raise ValueError(f"ciphertext for {type(self)} is not initialized, cannot produce wire format")
        _bytes = bytearray()
        _bytes += self._ephemeral.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        trailerlen = len(self._text)
        if self._sym_algo is not None:
            trailerlen += 1
        _bytes.append(trailerlen)
        if self._sym_algo is not None:
            _bytes.append(int(self._sym_algo))
        _bytes += self._text
        return _bytes

    def parse(self, packet: bytearray) -> None:
        self._ephemeral = self.pub_from_bytes(bytes(packet[:self.public_bytes]))
        del packet[:self.public_bytes]
        sz = packet[0]
        del packet[0]
        # for PKESKv3 ciphertexts, the symmetric key algorithm is
        # stuck in the clear outside of the ciphertext.
        if sz % 8 == 1:
            self._sym_algo = SymmetricKeyAlgorithm(packet[0])
            del packet[0]
            sz -= 1
        self._text = bytes(packet[:sz])
        del packet[:sz]


class X25519CipherText(NativeCFRGXCipherText):
    @property
    def public_bytes(self) -> int:
        return 32

    @property
    def aes_keywrap_keylen(self) -> int:
        return 16

    @property
    def hkdf_info(self) -> bytes:
        return b'OpenPGP X25519'

    def gen_priv(self) -> x25519.X25519PrivateKey:
        privkey = x25519.X25519PrivateKey.generate()
        self._ephemeral = privkey.public_key()
        return privkey

    def pub_from_bytes(self, b: bytes) -> x25519.X25519PublicKey:
        return x25519.X25519PublicKey.from_public_bytes(b)

    def kdf_hash_algo(self) -> cryptography_HashAlgorithm:
        return SHA256()


class X448CipherText(NativeCFRGXCipherText):
    @property
    def public_bytes(self) -> int:
        return 56

    @property
    def aes_keywrap_keylen(self) -> int:
        return 32

    @property
    def hkdf_info(self) -> bytes:
        return b'OpenPGP X448'

    def gen_priv(self) -> x448.X448PrivateKey:
        privkey = x448.X448PrivateKey.generate()
        self._ephemeral = privkey.public_key()
        return privkey

    def pub_from_bytes(self, b: bytes) -> x448.X448PublicKey:
        return x448.X448PublicKey.from_public_bytes(b)

    def kdf_hash_algo(self) -> cryptography_HashAlgorithm:
        return SHA512()
