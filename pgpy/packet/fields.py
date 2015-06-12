""" fields.py
"""
from __future__ import absolute_import, division

import abc
import collections
import hashlib
import itertools
import math
import os

from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type.univ import Integer
from pyasn1.type.univ import Sequence

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding

from .subpackets import Signature as SignatureSP
from .subpackets import UserAttribute
from .subpackets import signature
from .subpackets import userattribute

from .types import MPI
from .types import MPIs

from ..constants import EllipticCurveOID
from ..constants import HashAlgorithm
from ..constants import PubKeyAlgorithm
from ..constants import String2KeyType
from ..constants import SymmetricKeyAlgorithm

from ..decorators import sdproperty

from ..errors import PGPDecryptionError
from ..errors import PGPError

from ..symenc import _decrypt
from ..symenc import _encrypt

from ..types import Field

__all__ = ['SubPackets',
           'UserAttributeSubPackets',
           'Signature',
           'RSASignature',
           'DSASignature',
           'ECDSASignature',
           'PubKey',
           'OpaquePubKey',
           'RSAPub',
           'DSAPub',
           'ElGPub',
           'ECDSAPub',
           'String2Key',
           'PrivKey',
           'OpaquePrivKey',
           'RSAPriv',
           'DSAPriv',
           'ElGPriv',
           'ECDSAPriv',
           'CipherText',
           'RSACipherText',
           'ElGCipherText', ]


class SubPackets(collections.MutableMapping, Field):
    _spmodule = signature

    def __init__(self):
        super(SubPackets, self).__init__()
        self._hashed_sp = collections.OrderedDict()
        self._unhashed_sp = collections.OrderedDict()

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += self.__hashbytearray__()
        _bytes += self.__unhashbytearray__()
        return _bytes

    def __hashbytearray__(self):
        _bytes = bytearray()
        _bytes += self.int_to_bytes(sum(len(sp) for sp in self._hashed_sp.values()), 2)
        for hsp in self._hashed_sp.values():
            _bytes += hsp.__bytearray__()
        return _bytes

    def __unhashbytearray__(self):
        _bytes = bytearray()
        _bytes += self.int_to_bytes(sum(len(sp) for sp in self._unhashed_sp.values()), 2)
        for uhsp in self._unhashed_sp.values():
            _bytes += uhsp.__bytearray__()
        return _bytes

    def __len__(self):  # pragma: no cover
        return sum(sp.header.length for sp in itertools.chain(self._hashed_sp.values(), self._unhashed_sp.values())) + 4

    def __iter__(self):
        for sp in itertools.chain(self._hashed_sp.values(), self._unhashed_sp.values()):
            yield sp

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
        return key in set(k for k, _ in itertools.chain(self._hashed_sp, self._unhashed_sp))

    def addnew(self, spname, hashed=False, **kwargs):
        nsp = getattr(self._spmodule, spname)()
        for p, v in kwargs.items():
            if hasattr(nsp, p):
                setattr(nsp, p, v)
        nsp.update_hlen()
        if hashed:
            self['h_' + spname] = nsp

        else:
            self[spname] = nsp

    def update_hlen(self):
        for sp in self:
            sp.update_hlen()

    def parse(self, packet):
        hl = self.bytes_to_int(packet[:2])
        del packet[:2]

        # we do it this way because we can't ensure that subpacket headers are sized appropriately
        # for their contents, but we can at least output that correctly
        # so instead of tracking how many bytes we can now output, we track how many bytes have we parsed so far
        plen = len(packet)
        while plen - len(packet) < hl:
            sp = SignatureSP(packet)
            self['h_' + sp.__class__.__name__] = sp

        uhl = self.bytes_to_int(packet[:2])
        del packet[:2]

        plen = len(packet)
        while plen - len(packet) < uhl:
            sp = SignatureSP(packet)
            self[sp.__class__.__name__] = sp


class UserAttributeSubPackets(SubPackets):
    """
    This is nearly the same as just the unhashed subpackets from above,
    except that there isn't a length specifier. So, parse will only parse one packet,
    appending that one packet to self.__unhashed_sp.
    """
    _spmodule = userattribute

    def __bytearray__(self):
        _bytes = bytearray()
        for uhsp in self._unhashed_sp.values():
            _bytes += uhsp.__bytearray__()
        return _bytes

    def __len__(self):  # pragma: no cover
        return sum(len(sp) for sp in self._unhashed_sp.values())

    def parse(self, packet):
        # parse just one packet and add it to the unhashed subpacket ordereddict
        # I actually have yet to come across a User Attribute packet with more than one subpacket
        # which makes sense, given that there is only one defined subpacket
        sp = UserAttribute(packet)
        self[sp.__class__.__name__] = sp


class Signature(MPIs):
    def __bytearray__(self):
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


class RSASignature(Signature):
    def __init__(self):
        super(RSASignature, self).__init__()
        self.md_mod_n = MPI(0)

    def __iter__(self):
        yield self.md_mod_n

    def __sig__(self):
        return self.md_mod_n.to_mpibytes()[2:]

    def parse(self, packet):
        self.md_mod_n = MPI(packet)

    def from_signer(self, sig):
        self.md_mod_n = MPI(self.bytes_to_int(sig))


class DSASignature(Signature):
    def __init__(self):
        super(DSASignature, self).__init__()
        self.r = MPI(0)
        self.s = MPI(0)

    def __iter__(self):
        yield self.r
        yield self.s

    def __sig__(self):
        # return the signature data into an ASN.1 sequence of integers in DER format
        seq = Sequence()
        for i in self:
            seq.setComponentByPosition(len(seq), Integer(i))

        return encoder.encode(seq)

    def from_signer(self, sig):
        ##TODO: just use pyasn1 for this
        def _der_intf(_asn):
            if _asn[0] != 0x02:  # pragma: no cover
                raise ValueError("Expected: Integer (0x02). Got: 0x{:02X}".format(_asn[0]))
            del _asn[0]

            if _asn[0] & 0x80:  # pragma: no cover
                llen = _asn[0] & 0x7F
                del _asn[0]

                flen = self.bytes_to_int(_asn[:llen])
                del _asn[:llen]

            else:
                flen = _asn[0] & 0x7F
                del _asn[0]

            i = self.bytes_to_int(_asn[:flen])
            del _asn[:flen]
            return i

        if isinstance(sig, bytes):
            sig = bytearray(sig)

        # this is a very limited asn1 decoder - it is only intended to decode a DER encoded sequence of integers
        if not sig[0] == 0x30:
            raise NotImplementedError("Expected: Sequence (0x30). Got: 0x{:02X}".format(sig[0]))
        del sig[0]

        # skip the sequence length field
        if sig[0] & 0x80:  # pragma: no cover
            llen = sig[0] & 0x7F
            del sig[:llen + 1]

        else:
            del sig[0]

        self.r = MPI(_der_intf(sig))
        self.s = MPI(_der_intf(sig))

    def parse(self, packet):
        self.r = MPI(packet)
        self.s = MPI(packet)


class ECDSASignature(DSASignature):
    # def __init__(self):
    #     super(ECDSASignature, self).__init__()
    #     self.r = MPI(0)
    #     self.s = MPI(0)

    # def __iter__(self):
    #     yield self.r
    #     yield self.s

    # def __sig__(self):
    #     # return the signature data into an ASN.1 sequence of integers in DER format
    #     seq = Sequence()
    #     for i in self:
    #         seq.setComponentByPosition(len(seq), Integer(i))
    #
    #     return encoder.encode(seq)

    def from_signer(self, sig):
        seq, _ = decoder.decode(sig)
        self.r = MPI(seq[0])
        self.s = MPI(seq[1])


class PubKey(MPIs):
    @abc.abstractmethod
    def __pubkey__(self):
        """return the requisite *PublicKey class from the cryptography library"""

    def __bytearray__(self):
        _bytes = bytearray()
        for i in self:
            _bytes += i.to_mpibytes()
        return _bytes

    def publen(self):
        return len(self)

    def verify(self, subj, sigbytes, hash_alg):
        return NotImplemented


class OpaquePubKey(PubKey):
    def __init__(self):
        super(OpaquePubKey, self).__init__()
        self.data = bytearray()

    def __iter__(self):
        yield self.data

    def __pubkey__(self):
        return NotImplemented

    def __bytearray__(self):
        return self.data

    def parse(self, packet):
        ##TODO: this needs to be length-bounded to the end of the packet
        self.data = packet


class RSAPub(PubKey):
    def __init__(self):
        super(RSAPub, self).__init__()
        self.n = MPI(0)
        self.e = MPI(0)

    def __iter__(self):
        yield self.n
        yield self.e

    def __pubkey__(self):
        return rsa.RSAPublicNumbers(self.e, self.n).public_key(default_backend())

    def verify(self, subj, sigbytes, hash_alg):
        # zero-pad sigbytes if necessary
        sigbytes = (b'\x00' * (self.n.byte_length() - len(sigbytes))) + sigbytes
        verifier = self.__pubkey__().verifier(sigbytes, padding.PKCS1v15(), hash_alg)
        verifier.update(subj)

        try:
            verifier.verify()

        except InvalidSignature:
            return False

        return True

    def parse(self, packet):
        self.n = MPI(packet)
        self.e = MPI(packet)


class DSAPub(PubKey):
    def __init__(self):
        super(DSAPub, self).__init__()
        self.p = MPI(0)
        self.q = MPI(0)
        self.g = MPI(0)
        self.y = MPI(0)

    def __iter__(self):
        yield self.p
        yield self.q
        yield self.g
        yield self.y

    def __pubkey__(self):
        params = dsa.DSAParameterNumbers(self.p, self.q, self.g)
        return dsa.DSAPublicNumbers(self.y, params).public_key(default_backend())

    def verify(self, subj, sigbytes, hash_alg):
        verifier = self.__pubkey__().verifier(sigbytes, hash_alg)
        verifier.update(subj)

        try:
            verifier.verify()

        except InvalidSignature:
            return False

        return True

    def parse(self, packet):
        self.p = MPI(packet)
        self.q = MPI(packet)
        self.g = MPI(packet)
        self.y = MPI(packet)


class ElGPub(PubKey):
    def __init__(self):
        super(ElGPub, self).__init__()
        self.p = MPI(0)
        self.g = MPI(0)
        self.y = MPI(0)

    def __iter__(self):
        yield self.p
        yield self.g
        yield self.y

    def __pubkey__(self):
        raise NotImplementedError()

    def parse(self, packet):
        self.p = MPI(packet)
        self.g = MPI(packet)
        self.y = MPI(packet)


class ECDSAPub(PubKey):
    def __init__(self):
        super(ECDSAPub, self).__init__()
        self.oid = None
        self.x = MPI(0)
        self.y = MPI(0)

    def __iter__(self):
        yield self.x
        yield self.y

    def __len__(self):
        return sum([len(i) - 2 for i in self] + [3, len(encoder.encode(self.oid.value)) - 1])

    def __pubkey__(self):
        return ec.EllipticCurvePublicNumbers(self.x, self.y, self.oid.curve()).public_key(default_backend())

    def __bytearray__(self):
        _b = bytearray()
        _b += encoder.encode(self.oid.value)[1:]
        # 0x04 || x || y
        # where x and y are the same length
        _xy = b'\x04' + self.x.to_mpibytes()[2:] + self.y.to_mpibytes()[2:]
        _b += MPI(self.bytes_to_int(_xy, 'big')).to_mpibytes()

        return _b

    def verify(self, subj, sigbytes, hash_alg):
        verifier = self.__pubkey__().verifier(sigbytes, ec.ECDSA(hash_alg))
        verifier.update(subj)

        try:
            verifier.verify()

        except InvalidSignature:
            return False

        return True

    def parse(self, packet):
        oidlen = packet[0]
        print(oidlen)
        del packet[0]
        _oid = bytearray(b'\x06')
        _oid.append(oidlen)
        _oid += bytearray(packet[:oidlen])
        # try:
        oid, _  = decoder.decode(bytes(_oid))

        # except:
        #     raise PGPError("Bad OID octet stream: b'{:s}'".format(''.join(['\\x{:02X}'.format(c) for c in _oid])))
        self.oid = EllipticCurveOID(oid)
        del packet[:oidlen]

        # flen = (self.oid.bit_length // 8)
        xy = bytearray(MPI(packet).to_mpibytes()[2:])
        # xy = bytearray(MPI(packet).to_bytes(flen, 'big'))
        # the first byte is just \x04
        del xy[:1]
        # now xy needs to be separated into x, y
        xylen = len(xy)
        x, y = xy[:xylen // 2], xy[xylen // 2:]
        self.x = MPI(self.bytes_to_int(x))
        self.y = MPI(self.bytes_to_int(y))


class String2Key(Field):
    """
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
    @sdproperty
    def encalg(self):
        return self._encalg

    @encalg.register(int)
    @encalg.register(SymmetricKeyAlgorithm)
    def encalg_int(self, val):
        self._encalg = SymmetricKeyAlgorithm(val)

    @sdproperty
    def specifier(self):
        return self._specifier

    @specifier.register(int)
    @specifier.register(String2KeyType)
    def specifier_int(self, val):
        self._specifier = String2KeyType(val)

    @sdproperty
    def halg(self):
        return self._halg

    @halg.register(int)
    @halg.register(HashAlgorithm)
    def halg_int(self, val):
        self._halg = HashAlgorithm(val)

    @sdproperty
    def count(self):
        return (16 + (self._count & 15)) << ((self._count >> 4) + 6)

    @count.register(int)
    def count_int(self, val):
        self._count = val

    def __init__(self):
        super(String2Key, self).__init__()
        self.usage = 0
        self.encalg = 0
        self.specifier = 0
        self.iv = None

        # specifier-specific fields
        # simple, salted, iterated
        self.halg = 0

        # salted, iterated
        self.salt = bytearray()

        # iterated
        self.count = 0

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes.append(self.usage)
        if bool(self):
            _bytes.append(self.encalg)
            _bytes.append(self.specifier)
            if self.specifier >= String2KeyType.Simple:
                _bytes.append(self.halg)
            if self.specifier >= String2KeyType.Salted:
                _bytes += self.salt
            if self.specifier == String2KeyType.Iterated:
                _bytes.append(self._count)
            if self.iv is not None:
                _bytes += self.iv
        return _bytes

    def __len__(self):
        return len(self.__bytearray__())

    def __bool__(self):
        return self.usage in [254, 255]

    def __nonzero__(self):
        return self.__bool__()

    def parse(self, packet, iv=True):
        self.usage = packet[0]
        del packet[0]

        if bool(self):
            self.encalg = packet[0]
            del packet[0]

            self.specifier = packet[0]
            del packet[0]

            if self.specifier >= String2KeyType.Simple:
                # this will always be true
                self.halg = packet[0]
                del packet[0]

            if self.specifier >= String2KeyType.Salted:
                self.salt = packet[:8]
                del packet[:8]

            if self.specifier == String2KeyType.Iterated:
                self.count = packet[0]
                del packet[0]

            if iv:
                self.iv = packet[:(self.encalg.block_size // 8)]
                del packet[:(self.encalg.block_size // 8)]

    def derive_key(self, passphrase):
        ##TODO: raise an exception if self.usage is not 254 or 255
        keylen = self.encalg.key_size
        hashlen = self.halg.digest_size * 8

        ctx = int(math.ceil((keylen / hashlen)))

        # Simple S2K - always done
        hsalt = b''
        hpass = passphrase.encode('latin-1')

        # salted, iterated S2K
        if self.specifier >= String2KeyType.Salted:
            hsalt = bytes(self.salt)

        count = len(hsalt + hpass)
        if self.specifier == String2KeyType.Iterated and self.count > len(hsalt + hpass):
            count = self.count

        hcount = (count // len(hsalt + hpass))
        hleft = count - (hcount * len(hsalt + hpass))

        hashdata = ((hsalt + hpass) * hcount) + (hsalt + hpass)[:hleft]

        h = []
        for i in range(0, ctx):
            _h = self.halg.hasher
            _h.update(b'\x00' * i)
            _h.update(hashdata)
            h.append(_h)

        # GC some stuff
        del hsalt
        del hpass
        del hashdata

        # and return the key!
        return b''.join(hc.digest() for hc in h)[:(keylen // 8)]


class PrivKey(PubKey):
    def __init__(self):
        super(PrivKey, self).__init__()
        self.s2k = String2Key()
        self.encbytes = bytearray()
        self.chksum = bytearray()

    def __bytearray__(self):
        pubitems = len(list(super(self.__class__, self).__iter__()))
        _bytes = bytearray()
        for n, i in enumerate(self):
            if n == pubitems:
                _bytes += self.s2k.__bytearray__()

                if self.s2k:
                    _bytes += self.encbytes
                    break

            _bytes += i.to_mpibytes() if isinstance(i, MPI) else i

        if self.s2k.usage == 0:
            _bytes += self.chksum

        return _bytes

    def __len__(self):
        l = super(PrivKey, self).__len__() if not self.encbytes else (self.publen() + len(self.encbytes))
        return l + sum([len(self.s2k), len(self.chksum)])

    @abc.abstractmethod
    def __privkey__(self):
        """return the requisite *PrivateKey class from the cryptography library"""

    @abc.abstractmethod
    def _generate(self, key_size):
        """Generate a new PrivKey"""

    def _compute_chksum(self):
        chs = sum(sum(bytearray(c.to_mpibytes())) for c in self) % 65536
        self.chksum = bytearray(self.int_to_bytes(chs, 2))

    def publen(self):
        return sum(len(i) for i in super(self.__class__, self).__iter__())

    # @abc.abstractmethod
    def encrypt_keyblob(self, passphrase, enc_alg, hash_alg):
        # PGPy will only ever use iterated and salted S2k mode
        self.s2k.usage = 254
        self.s2k.encalg = enc_alg
        self.s2k.specifier = String2KeyType.Iterated
        self.s2k.iv = enc_alg.gen_iv()
        self.s2k.halg = hash_alg
        self.s2k.salt = bytearray(os.urandom(8))
        self.s2k.count = hash_alg.tuned_count

        # now that String-to-Key is ready to go, derive sessionkey from passphrase
        # and then unreference passphrase
        sessionkey = self.s2k.derive_key(passphrase)
        del passphrase

        pubitems = len(list(super(self.__class__, self).__iter__()))
        pt = bytearray()
        for n, i in enumerate(self):
            # skip public key components
            if n < pubitems:
                continue

            pt += i.to_mpibytes() if isinstance(i, MPI) else i

        # append a SHA-1 hash of the plaintext so far to the plaintext
        pt += hashlib.new('sha1', pt).digest()

        # encrypt
        self.encbytes = bytearray(_encrypt(bytes(pt), bytes(sessionkey), enc_alg, bytes(self.s2k.iv)))

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
        pt = _decrypt(bytes(self.encbytes), bytes(sessionkey), self.s2k.encalg, bytes(self.s2k.iv))

        # check the hash to see if we decrypted successfully or not
        if self.s2k.usage == 254 and not pt[-20:] == hashlib.new('sha1', pt[:-20]).digest():
            # if the usage byte is 254, key material is followed by a 20-octet sha-1 hash of the rest
            # of the key material block
            raise PGPDecryptionError("Passphrase was incorrect!")

        if self.s2k.usage == 255 and not self.bytes_to_int(pt[-2:]) == (sum(bytearray(pt[:-2])) % 65536):  # pragma: no cover
            # if the usage byte is 255, key material is followed by a 2-octet checksum of the rest
            # of the key material block
            raise PGPDecryptionError("Passphrase was incorrect!")

        return bytearray(pt)

    def sign(self, sigdata, hash_alg):
        return NotImplemented

    @abc.abstractmethod
    def clear(self):
        """delete and re-initialize as zero, all private components"""


class OpaquePrivKey(PrivKey, OpaquePubKey):
    def __privkey__(self):
        return NotImplemented

    def _generate(self, key_size):
        # return NotImplemented
        raise NotImplementedError()

    def decrypt_keyblob(self, passphrase):
        return NotImplemented

    def clear(self):
        del self.data
        self.data = bytearray()


class RSAPriv(PrivKey, RSAPub):
    def __init__(self):
        super(RSAPriv, self).__init__()
        self.d = MPI(0)
        self.p = MPI(0)
        self.q = MPI(0)
        self.u = MPI(0)

    def __iter__(self):
        for i in RSAPub.__iter__(self):
            yield i
        yield self.d
        yield self.p
        yield self.q
        yield self.u

    def __privkey__(self):
        return rsa.RSAPrivateNumbers(self.p, self.q, self.d,
                                     rsa.rsa_crt_dmp1(self.d, self.p),
                                     rsa.rsa_crt_dmq1(self.d, self.q),
                                     rsa.rsa_crt_iqmp(self.p, self.q),
                                     rsa.RSAPublicNumbers(self.e, self.n)).private_key(default_backend())

    def _generate(self, key_size):
        if any(c != 0 for c in self):
            ##TODO:
            raise PGPError("key is already populated")

        # generate some big numbers!
        pk = rsa.generate_private_key(65537, key_size, default_backend())
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

    def parse(self, packet):
        super(RSAPriv, self).parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.d = MPI(packet)
            self.p = MPI(packet)
            self.q = MPI(packet)
            self.u = MPI(packet)

            if self.s2k.usage == 0:
                self.chksum = packet[:2]
                del packet[:2]

        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

    def decrypt_keyblob(self, passphrase):
        kb = super(RSAPriv, self).decrypt_keyblob(passphrase)
        del passphrase

        self.d = MPI(kb)
        self.p = MPI(kb)
        self.q = MPI(kb)
        self.u = MPI(kb)

        if self.s2k.usage in [254, 255]:
            self.chksum = kb
            del kb

    def sign(self, sigdata, hash_alg):
        signer = self.__privkey__().signer(padding.PKCS1v15(), hash_alg)
        signer.update(sigdata)
        return signer.finalize()

    def clear(self):
        del self.d
        del self.p
        del self.q
        del self.u
        self.d = MPI(0)
        self.p = MPI(0)
        self.q = MPI(0)
        self.u = MPI(0)


class DSAPriv(PrivKey, DSAPub):
    def __init__(self):
        super(DSAPriv, self).__init__()
        self.x = 0

    def __iter__(self):
        for i in DSAPub.__iter__(self):
            yield i
        yield self.x

    def __privkey__(self):
        params = dsa.DSAParameterNumbers(self.p, self.q, self.g)
        pn = dsa.DSAPublicNumbers(self.y, params)
        return dsa.DSAPrivateNumbers(self.x, pn).private_key(default_backend())

    def _generate(self, key_size):
        if any(c != 0 for c in self):
            ##TODO:
            raise PGPError("key is already populated")

        # generate some big numbers!
        pk = dsa.generate_private_key(key_size, default_backend())
        pkn = pk.private_numbers()

        self.p = MPI(pkn.public_numbers.parameter_numbers.p)
        self.q = MPI(pkn.public_numbers.parameter_numbers.q)
        self.g = MPI(pkn.public_numbers.parameter_numbers.g)
        self.y = MPI(pkn.public_numbers.y)
        self.x = MPI(pkn.x)

        del pkn
        del pk

        self._compute_chksum()

    def parse(self, packet):
        super(DSAPriv, self).parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.x = MPI(packet)

        else:
            self.encbytes = packet

        if self.s2k.usage in [0, 255]:
            self.chksum = packet[:2]
            del packet[:2]

    def decrypt_keyblob(self, passphrase):
        kb = super(DSAPriv, self).decrypt_keyblob(passphrase)
        del passphrase

        self.x = MPI(kb)

        if self.s2k.usage in [254, 255]:
            self.chksum = kb
            del kb

    def clear(self):
        del self.x
        self.x = MPI(0)

    def sign(self, sigdata, hash_alg):
        signer = self.__privkey__().signer(hash_alg)
        signer.update(sigdata)
        return signer.finalize()


class ElGPriv(PrivKey, ElGPub):
    def __init__(self):
        super(ElGPriv, self).__init__()
        self.x = MPI(0)

    def __iter__(self):
        for i in ElGPub.__iter__(self):
            yield i
        yield self.x

    def __privkey__(self):
        raise NotImplementedError()

    def _generate(self, key_size):
        raise NotImplementedError(PubKeyAlgorithm.ElGamal)

    def parse(self, packet):
        super(ElGPriv, self).parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.x = MPI(packet)

        else:
            self.encbytes = packet

        if self.s2k.usage in [0, 255]:
            self.chksum = packet[:2]
            del packet[:2]

    def decrypt_keyblob(self, passphrase):
        kb = super(ElGPriv, self).decrypt_keyblob(passphrase)
        del passphrase

        self.x = MPI(kb)

        if self.s2k.usage in [254, 255]:
            self.chksum = kb
            del kb

    def clear(self):
        del self.x
        self.x = MPI(0)


class ECDSAPriv(PrivKey, ECDSAPub):
    def __init__(self):
        super(ECDSAPriv, self).__init__()
        self.s = MPI(0)

    def __iter__(self):
        for i in ECDSAPub.__iter__(self):
            yield i
        yield self.s

    def __bytearray__(self):
        _b = ECDSAPub.__bytearray__(self)
        _b += self.s2k.__bytearray__()
        if not self.s2k:
            _b += self.s.to_mpibytes()

            if self.s2k.usage == 0:
                _b += self.chksum

        else:
            _b += self.encbytes

        return _b

    def __len__(self):
        return sum([self.publen(),
                    len(self.s) if not self.encbytes else len(self.encbytes),
                    len(self.s2k),
                    len(self.chksum)])

    def __privkey__(self):
        ecp = ec.EllipticCurvePublicNumbers(self.x, self.y, self.oid.curve())
        return ec.EllipticCurvePrivateNumbers(self.s, ecp).private_key(default_backend())

    def _generate(self, oid):
        if any(c != 0 for c in self):
            raise PGPError("Key is already populated!")

        self.oid = EllipticCurveOID(oid)

        pk = ec.generate_private_key(self.oid.value, default_backend())
        pubn = pk.public_key().public_numbers()
        self.x = pubn.x
        self.y = pubn.y
        self.s = pk.private_numbers().private_value

    def publen(self):
        return sum([len(i) - 2 for i in ECDSAPub.__iter__(self)] + [3, len(encoder.encode(self.oid.value)) - 1])

    def parse(self, packet):
        super(ECDSAPriv, self).parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.s = MPI(packet)

            if self.s2k.usage == 0:
                self.chksum = packet[:2]
                del packet[:2]

        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

    def decrypt_keyblob(self, passphrase):
        raise NotImplementedError("ECDSA private key unlocking is not implemented yet")

    def clear(self):
        del self.oid
        del self.x
        del self.y
        del self.s

        self.oid = None
        self.x = MPI(0)
        self.y = MPI(0)
        self.s = MPI(0)

    def sign(self, sigdata, hash_alg):
        signer = self.__privkey__().signer(ec.ECDSA(hash_alg))
        signer.update(sigdata)
        return signer.finalize()


class CipherText(MPIs):
    def __bytearray__(self):
        _bytes = bytearray()
        for i in self:
            _bytes += i.to_mpibytes()
        return _bytes

    @abc.abstractmethod
    def from_encrypter(self, ct):
        """create and parse a concrete CipherText class instance"""


class RSACipherText(CipherText):
    def __init__(self):
        super(RSACipherText, self).__init__()
        self.me_mod_n = MPI(0)

    def __iter__(self):
        yield self.me_mod_n

    def parse(self, packet):
        self.me_mod_n = MPI(packet)

    def from_encrypter(self, ct):
        self.me_mod_n = MPI(self.bytes_to_int(ct))


class ElGCipherText(CipherText):
    def __init__(self):
        super(ElGCipherText, self).__init__()
        self.gk_mod_p = MPI(0)
        self.myk_mod_p = MPI(0)

    def __iter__(self):  # pragma: no cover
        yield self.gk_mod_p
        yield self.myk_mod_p

    def parse(self, packet):
        self.gk_mod_p = MPI(packet)
        self.myk_mod_p = MPI(packet)

    def from_encrypter(self, ct):
        raise NotImplementedError()
