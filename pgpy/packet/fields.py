""" fields.py
"""

import abc
import binascii
import collections
import copy
import itertools
import math
import os

import collections.abc

from typing import Optional, Tuple, Union

from warnings import warn

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import utils

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
from ..constants import HashAlgorithm
from ..constants import PubKeyAlgorithm
from ..constants import String2KeyType
from ..constants import S2KGNUExtension
from ..constants import SymmetricKeyAlgorithm
from ..constants import S2KUsage

from ..decorators import sdproperty

from ..errors import PGPDecryptionError
from ..errors import PGPError
from ..errors import PGPIncompatibleECPointFormatError

from ..symenc import _cfb_decrypt
from ..symenc import _cfb_encrypt

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
           'PubKey',
           'OpaquePubKey',
           'RSAPub',
           'DSAPub',
           'ElGPub',
           'ECPoint',
           'ECDSAPub',
           'EdDSAPub',
           'ECDHPub',
           'S2KSpecifier',
           'String2Key',
           'ECKDF',
           'PrivKey',
           'OpaquePrivKey',
           'RSAPriv',
           'DSAPriv',
           'ElGPriv',
           'ECDSAPriv',
           'EdDSAPriv',
           'ECDHPriv',
           'CipherText',
           'RSACipherText',
           'ElGCipherText',
           'ECDHCipherText', ]


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
        raise NotImplementedError

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


class PubKey(MPIs):
    __pubfields__: Tuple = ()
    __pubkey_algo__: Optional[PubKeyAlgorithm] = None

    @property
    def __mpis__(self):
        yield from self.__pubfields__

    def __init__(self):
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

    def __len__(self):
        return sum(len(getattr(self, i)) for i in self.__pubfields__)

    def __bytearray__(self):
        _bytes = bytearray()
        for field in self.__pubfields__:
            _bytes += getattr(self, field).to_mpibytes()

        return _bytes

    def publen(self):
        return len(self)

    def verify(self, subj, sigbytes, hash_alg):
        return NotImplemented  # pragma: no cover


class OpaquePubKey(PubKey):  # pragma: no cover
    def __init__(self):
        super().__init__()
        self.data = bytearray()

    def __iter__(self):
        yield self.data

    def __pubkey__(self):
        return NotImplemented

    def __bytearray__(self) -> bytearray:
        return self.data

    def parse(self, packet: bytearray) -> None:
        ##TODO: this needs to be length-bounded to the end of the packet
        self.data = packet


class RSAPub(PubKey):
    __pubfields__ = ('n', 'e')
    __pubkey_algo__ = PubKeyAlgorithm.RSAEncryptOrSign

    def __pubkey__(self):
        return rsa.RSAPublicNumbers(self.e, self.n).public_key()

    def verify(self, subj, sigbytes, hash_alg):
        # zero-pad sigbytes if necessary
        sigbytes = (b'\x00' * (self.n.byte_length() - len(sigbytes))) + sigbytes
        try:
            self.__pubkey__().verify(sigbytes, subj, padding.PKCS1v15(), hash_alg)
        except InvalidSignature:
            return False
        return True

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

    def __copy__(self) -> 'ECPoint':
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

    def __copy__(self) -> 'ECDSAPub':
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

    def __copy__(self) -> 'EdDSAPub':
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
        if self.oid == EllipticCurveOID.Curve25519:
            return x25519.X25519PublicKey.from_public_bytes(self.p.x)
        else:
            return ec.EllipticCurvePublicNumbers(self.p.x, self.p.y, self.oid.curve()).public_key()

    def __bytearray__(self) -> bytearray:
        _b = bytearray()
        _b += bytes(self.oid)
        _b += self.p.to_mpibytes()
        _b += self.kdf.__bytearray__()
        return _b

    def __copy__(self) -> 'ECDHPub':
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
            if self.oid == EllipticCurveOID.Curve25519:
                if self.p.format != ECPointFormat.Native:
                    raise PGPIncompatibleECPointFormatError("Only Native format is valid for Curve25519")
            elif self.p.format != ECPointFormat.Standard:
                raise PGPIncompatibleECPointFormatError("Only Standard format is valid for this curve")
        else:
            self.p = MPI(packet)

        self.kdf.parse(packet)


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
        super().__init__()
        self._type: String2KeyType = s2ktype
        self._halg: HashAlgorithm = halg
        self._salt: Optional[bytes] = None
        if salt is not None:
            self._salt = bytes(salt)
        self._count = 65011712  # the default!
        if s2ktype is String2KeyType.Iterated:
            self.iteration_count = iteration_count
        self._gnupg_extension: S2KGNUExtension = gnupg_extension
        self._smartcard_serial: Optional[bytes] = None
        if smartcard_serial is not None:
            self.smartcard_serial = bytes(smartcard_serial)

    def __copy__(self) -> "S2KSpecifier":
        s2k = S2KSpecifier()
        s2k._type = self._type
        if self._type is String2KeyType.Unknown:
            s2k._opaque_type = self._opaque_type

        s2k._halg = self._halg
        s2k._salt = copy.copy(self._salt)
        s2k._count = self._count
        s2k._gnupg_extension = self._gnupg_extension
        s2k._smartcard_serial = copy.copy(self._smartcard_serial)
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

        if self._type == String2KeyType.Iterated:
            self.iteration_count = packet[:1]
            del packet[:1]

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
        if self._type not in {String2KeyType.Simple, String2KeyType.Salted, String2KeyType.Iterated}:
            raise NotImplementedError(f"Cannot derive key from S2KSpecifier {self._type!r}")

        if not isinstance(passphrase, bytes):
            passphrase = passphrase.encode('utf-8')

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
    This contains an S2KUsage flag.  Depending on the S2KUsage flag, it can also contain an S2KSpecifier, an encryption algorithm, and an IV.
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
        elif self.usage in [S2KUsage.MalleableCFB, S2KUsage.CFB]:
            if not self._specifier._type.has_iv:
                # this is likely some sort of weird extension case
                return 0
            return self.encalg.block_size // 8
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

    def __init__(self) -> None:
        super().__init__()
        self.usage = S2KUsage.Unprotected
        self._encalg = SymmetricKeyAlgorithm.AES256
        self._specifier = S2KSpecifier()
        self._iv = None

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        _bytes.append(self.usage)
        if bool(self):
            _bytes.append(self.encalg)
            _bytes += self._specifier.__bytearray__()
            if self.iv is not None:
                _bytes += self.iv
        return _bytes

    def __len__(self) -> int:
        return len(self.__bytearray__())

    def __bool__(self) -> bool:
        return self.usage in [S2KUsage.CFB, S2KUsage.MalleableCFB]

    def __copy__(self) -> 'String2Key':
        s2k = String2Key()
        s2k.usage = self.usage
        s2k.encalg = self.encalg
        s2k._specifier = copy.copy(self._specifier)

        s2k.iv = self.iv
        return s2k

    def parse(self, packet: bytearray) -> None:
        self.usage = S2KUsage(packet[0])
        del packet[0]

        if bool(self):
            self.encalg = SymmetricKeyAlgorithm(packet[0])
            del packet[0]

            self._specifier.parse(packet)
            if self.encalg is not SymmetricKeyAlgorithm.Plaintext:
                ivlen = self._iv_length
                if ivlen:
                    self.iv = packet[:(ivlen)]
                    del packet[:(ivlen)]

    def derive_key(self, passphrase) -> bytes:
        derivable = {S2KUsage.MalleableCFB, S2KUsage.CFB}
        if self.usage not in derivable:
            raise ValueError(f"can only derive key from String2Key object when usage octet is {derivable}, not {self.usage}")
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

    def __init__(self):
        super().__init__()

        self.s2k = String2Key()
        self.encbytes = bytearray()
        self.chksum = bytearray()

        for field in self.__privfields__:
            setattr(self, field, MPI(0))

    def _append_private_fields(self, _bytes: bytearray) -> None:
        '''override this function if the private fields are not MPIs'''
        for field in self.__privfields__:
            _bytes += getattr(self, field).to_mpibytes()

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += super().__bytearray__()

        _bytes += self.s2k.__bytearray__()
        if self.s2k:
            _bytes += self.encbytes

        else:
            self._append_private_fields(_bytes)

        if self.s2k.usage is S2KUsage.Unprotected:
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

    def encrypt_keyblob(self, passphrase: str,
                        enc_alg: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES256,
                        hash_alg: Optional[HashAlgorithm] = None,
                        s2kspec: Optional[S2KSpecifier] = None,
                        iv: Optional[bytes] = None) -> None:
        # PGPy will only ever use iterated and salted S2k mode
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

        # now that String-to-Key is ready to go, derive sessionkey from passphrase
        # and then unreference passphrase
        sessionkey = self.s2k.derive_key(passphrase)
        del passphrase

        pt = bytearray()
        self._append_private_fields(pt)

        # append a SHA-1 hash of the plaintext so far to the plaintext
        pt += HashAlgorithm.SHA1.digest(pt)

        # encrypt
        self.encbytes = bytearray(_cfb_encrypt(bytes(pt), bytes(sessionkey), enc_alg, bytes(self.s2k.iv)))

        # delete pt and clear self
        del pt
        self.clear()

    @abc.abstractmethod
    def decrypt_keyblob(self, passphrase):
        if not self.s2k:  # pragma: no cover
            # not encrypted
            return

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
        return NotImplemented  # pragma: no cover

    def clear(self):
        """delete and re-initialize all private components to zero"""
        for field in self.__privfields__:
            delattr(self, field)
            setattr(self, field, MPI(0))


class OpaquePrivKey(PrivKey, OpaquePubKey):  # pragma: no cover
    def __privkey__(self):
        return NotImplemented

    def _generate(self, key_size_or_oid: Optional[Union[int, EllipticCurveOID]]) -> None:
        # return NotImplemented
        raise NotImplementedError()

    def decrypt_keyblob(self, passphrase):
        return NotImplemented


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

    def decrypt_keyblob(self, passphrase):
        kb = super().decrypt_keyblob(passphrase)
        del passphrase

        self.d = MPI(kb)
        self.p = MPI(kb)
        self.q = MPI(kb)
        self.u = MPI(kb)

        if self.s2k.usage in {S2KUsage.CFB, S2KUsage.MalleableCFB}:
            self.chksum = kb
            del kb

    def sign(self, sigdata: bytes, hash_alg: HashAlgorithm) -> bytes:
        return self.__privkey__().sign(sigdata, padding.PKCS1v15(), hash_alg)


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

    def decrypt_keyblob(self, passphrase):
        kb = super().decrypt_keyblob(passphrase)
        del passphrase

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

    def decrypt_keyblob(self, passphrase):
        kb = super().decrypt_keyblob(passphrase)
        del passphrase

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

    def decrypt_keyblob(self, passphrase):
        kb = super().decrypt_keyblob(passphrase)
        del passphrase
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

        if self.oid != EllipticCurveOID.Ed25519:
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

    def decrypt_keyblob(self, passphrase):
        kb = super().decrypt_keyblob(passphrase)
        del passphrase
        self.s = MPI(kb)

    def sign(self, sigdata, hash_alg):
        # GnuPG requires a pre-hashing with EdDSA
        # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-06#section-14.8
        digest = hashes.Hash(hash_alg)
        digest.update(sigdata)
        sigdata = digest.finalize()
        return self.__privkey__().sign(sigdata)


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
        if self.oid == EllipticCurveOID.Curve25519:
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

        if _oid == EllipticCurveOID.Curve25519:
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


class CipherText(MPIs):
    def __init__(self):
        super().__init__()
        for i in self.__mpis__:
            setattr(self, i, MPI(0))

    @classmethod
    @abc.abstractmethod
    def encrypt(cls, encfn, *args):
        """create and populate a concrete CipherText class instance"""

    @abc.abstractmethod
    def decrypt(self, decfn, *args):
        """decrypt the ciphertext contained in this CipherText instance"""

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray()
        for i in self:
            _bytes += i.to_mpibytes()
        return _bytes


class RSACipherText(CipherText):
    __mpis__ = ('me_mod_n', )

    @classmethod
    def encrypt(cls, encfn, *args):
        ct = cls()
        ct.me_mod_n = MPI(cls.bytes_to_int(encfn(*args)))
        return ct

    def decrypt(self, decfn, *args):
        return decfn(*args)

    def parse(self, packet: bytearray) -> None:
        self.me_mod_n = MPI(packet)


class ElGCipherText(CipherText):
    __mpis__ = ('gk_mod_p', 'myk_mod_p')

    @classmethod
    def encrypt(cls, encfn, *args):
        raise NotImplementedError()

    def decrypt(self, decfn, *args):
        raise NotImplementedError()

    def parse(self, packet: bytearray) -> None:
        self.gk_mod_p = MPI(packet)
        self.myk_mod_p = MPI(packet)


class ECDHCipherText(CipherText):
    __mpis__ = ('p',)

    @classmethod
    def encrypt(cls, pk, *args):
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
        # *args should be:
        # - m
        #
        _m, = args

        # m may need to be PKCS5-padded
        padder = PKCS7(64).padder()
        m = padder.update(_m) + padder.finalize()

        km = pk.keymaterial
        ct = cls()

        # generate ephemeral key pair and keep public key in ct
        # use private key to compute the shared point "s"
        if km.oid == EllipticCurveOID.Curve25519:
            v = x25519.X25519PrivateKey.generate()
            x = v.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            ct.p = ECPoint.from_values(km.oid.key_size, ECPointFormat.Native, x)
            s = v.exchange(km.__pubkey__())
        else:
            v = ec.generate_private_key(km.oid.curve())
            x = MPI(v.public_key().public_numbers().x)
            y = MPI(v.public_key().public_numbers().y)
            ct.p = ECPoint.from_values(km.oid.key_size, ECPointFormat.Standard, x, y)
            s = v.exchange(ec.ECDH(), km.__pubkey__())

        # derive the wrapping key
        z = km.kdf.derive_key(s, km.oid, PubKeyAlgorithm.ECDH, pk.fingerprint)

        # compute C
        ct.c = aes_key_wrap(z, m)

        return ct

    def decrypt(self, pk, *args):
        km = pk.keymaterial
        if km.oid == EllipticCurveOID.Curve25519:
            v = x25519.X25519PublicKey.from_public_bytes(self.p.x)
            s = km.__privkey__().exchange(v)
        else:
            # assemble the public component of ephemeral key v
            v = ec.EllipticCurvePublicNumbers(self.p.x, self.p.y, km.oid.curve()).public_key()
            # compute s using the inverse of how it was derived during encryption
            s = km.__privkey__().exchange(ec.ECDH(), v)

        # derive the wrapping key
        z = km.kdf.derive_key(s, km.oid, PubKeyAlgorithm.ECDH, pk.fingerprint)

        # unwrap and unpad m
        _m = aes_key_unwrap(z, self.c)

        padder = PKCS7(64).unpadder()
        return padder.update(_m) + padder.finalize()

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
