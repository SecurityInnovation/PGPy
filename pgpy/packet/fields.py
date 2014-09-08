""" fields.py
"""
# Python 2.7 shenanigans
from __future__ import division

import abc
import collections
import hashlib
import itertools
import math
import time

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa

from .subpackets import Signature as SignatureSP
from .subpackets import UserAttribute

from .types import MPI
from .types import MPIs

from ..constants import HashAlgorithm
from ..constants import String2KeyType
from ..constants import SymmetricKeyAlgorithm

from ..decorators import TypedProperty

from ..errors import PGPDecryptionError

from ..symenc import _decrypt

from ..types import Field

from ..util import modinv


class SubPackets(collections.MutableMapping, Field):
    def __init__(self):
        self._hashed_sp = collections.OrderedDict()
        self._unhashed_sp = collections.OrderedDict()

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += self.__hashbytes__()
        _bytes += self.__unhashbytes__()
        return bytes(_bytes)

    def __hashbytes__(self):
        _bytes = bytearray()
        _bytes += self.int_to_bytes(sum(len(sp) for sp in self._hashed_sp.values()), 2)
        _bytes += b''.join(hsp.__bytes__() for hsp in self._hashed_sp.values())
        return bytes(_bytes)

    def __unhashbytes__(self):
        _bytes = bytearray()
        _bytes += self.int_to_bytes(sum(len(sp) for sp in self._unhashed_sp.values()), 2)
        _bytes += b''.join(uhsp.__bytes__() for uhsp in self._unhashed_sp.values())
        return bytes(_bytes)

    def __len__(self):
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
        if not isinstance(key, tuple):
            i = 0
            while (key, i) in self:
                i += 1
            key = (key, i)

        if key[0].startswith('h_'):
            self._hashed_sp[(key[0][2:], i)] = val

        else:
            self._unhashed_sp[key] = val

    def __getitem__(self, key):
        if isinstance(key, tuple):
            return self._hashed_sp[key]

        if key.startswith('h_'):
            return [v for k, v in self._hashed_sp.items() if key[2:] == k[0]]

        else:
            return [v for k, v in itertools.chain(self._hashed_sp.items(), self._unhashed_sp.items()) if key == k[0]]

    def __delitem__(self, key):
        ##TODO: this
        pass

    def __contains__(self, key):
        return any([key in [dk[0] for dk in self._hashed_sp.keys()],
                    key in [dk[0] for dk in self._unhashed_sp.keys()]])

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
    def __bytes__(self):
        return b''.join(uhsp.__bytes__() for uhsp in self._unhashed_sp.values())

    def __len__(self):
        return sum(len(sp) for sp in self._unhashed_sp.values())

    def parse(self, packet):
        # parse just one packet and add it to the unhashed subpacket ordereddict
        # I actually have yet to come across a User Attribute packet with more than one subpacket
        # which makes sense, given that there is only one defined subpacket
        sp = UserAttribute(packet)
        self[sp.__class__.__name__] = sp


class Signature(MPIs):
    def __bytes__(self):
        return b''.join(i.to_mpibytes() for i in self)

    @abc.abstractproperty
    def __sig__(self):
        return b''

    @abc.abstractmethod
    def from_signer(self, sig):
        pass


class RSASignature(Signature):
    def __init__(self):
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
        self.r = MPI(0)
        self.s = MPI(0)

    def __iter__(self):
        yield self.r
        yield self.s

    def __sig__(self):
        # return the signature data into an ASN.1 sequence of integers in DER format
        # (see http://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One#Example_encoded_in_DER)

        def _der_flen(i):
            _b = b''
            # returns the length of byte field i
            ilen = len(i)
            bilen = self.int_to_bytes(ilen)

            # long-form must be used ilen > 127
            if len(bilen) > 127:
                _b += 0x80 ^ len(bilen)
            return _b + bilen

        def _der_intf(i):
            bf = self.int_to_bytes(i, i.byte_length())
            return b'\x02' + _der_flen(bf) + bf

        # construct the sequence of integers
        fbytes = b''.join([_der_intf(i) for i in self])

        # now mark it as a sequence and return
        return b'\x30' + _der_flen(fbytes) + fbytes

    def from_signer(self, sig):
        def _der_intf(_asn):
            if _asn[0] != 0x02:
                raise ValueError("Expected: Integer (0x02). Got: 0x{:02X}".format(_asn[0]))
            del _asn[0]

            if _asn[0] & 0x80:
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
        if sig[0] & 0x80:
            llen = sig[0] & 0x7F
            del sig[:llen + 1]

        else:
            del sig[0]

        self.r = MPI(_der_intf(sig))
        self.s = MPI(_der_intf(sig))

    def parse(self, packet):
        self.r = MPI(packet)
        self.s = MPI(packet)


class PubKey(MPIs):
    @abc.abstractmethod
    def __pubkey__(self):
        return None

    def __bytes__(self):
        return b''.join(i.to_mpibytes() for i in self)

    def publen(self):
        return len(self)


class RSAPub(PubKey):
    def __init__(self):
        self.n = MPI(0)
        self.e = MPI(0)

    def __iter__(self):
        yield self.n
        yield self.e

    def __pubkey__(self):
        return rsa.RSAPublicKey(public_exponent=self.e, modulus=self.n)

    def parse(self, packet):
        self.n = MPI(packet)
        self.e = MPI(packet)


class DSAPub(PubKey):
    def __init__(self):
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
        return dsa.DSAPublicKey(modulus=self.p,
                                subgroup_order=self.q,
                                generator=self.g,
                                y=self.y)

    def parse(self, packet):
        self.p = MPI(packet)
        self.q = MPI(packet)
        self.g = MPI(packet)
        self.y = MPI(packet)


class ElGPub(PubKey):
    def __init__(self):
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
    @TypedProperty
    def encalg(self):
        return self._encalg

    @encalg.SymmetricKeyAlgorithm
    def encalg(self, val):
        self._encalg = val

    @encalg.int
    def encalg(self, val):
        self.encalg = SymmetricKeyAlgorithm(val)

    @TypedProperty
    def specifier(self):
        return self._specifier

    @specifier.String2KeyType
    def specifier(self, val):
        self._specifier = val

    @specifier.int
    def specifier(self, val):
        self.specifier = String2KeyType(val)

    @TypedProperty
    def halg(self):
        return self._halg

    @halg.HashAlgorithm
    def halg(self, val):
        self._halg = val

    @halg.int
    def halg(self, val):
        self.halg = HashAlgorithm(val)

    @TypedProperty
    def count(self):
        return (16 + (self._count & 15)) << ((self._count >> 4) + 6)

    @count.int
    def count(self, val):
        self._count = val

    def __init__(self):
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

    def __bytes__(self):
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
        return bytes(_bytes)

    def __len__(self):
        return len(self.__bytes__())

    def __bool__(self):
        return self.usage in [254, 255]

    # Python 2.7 shenanigans
    def __nonzero__(self):
        return self.usage in [254, 255]

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
        self.s2k = String2Key()
        self.encbytes = bytearray()
        self.chksum = 0

    def __bytes__(self):
        # select the parent class that is a public key to iterate over the public key fields first
        # and then
        # pubc = [c for c in self.__class__.mro() if issubclass(c, PubKey) and not issubclass(c, PrivKey)][0]
        pubitems = len(list(super(self.__class__, self).__iter__()))
        _bytes = bytearray()
        for n, i in enumerate(self):
            if n == pubitems:
                _bytes += self.s2k.__bytes__()

                if self.s2k:
                    _bytes += self.encbytes
                    break

            _bytes += i.to_mpibytes()

        if self.s2k.usage == 0:
            _bytes += self.chksum

        return bytes(_bytes)

    def __len__(self):
        return super(PrivKey, self).__len__() + len(self.s2k)

    @abc.abstractmethod
    def __privkey__(self):
        return None

    def publen(self):
        return sum(len(i) for i in super(self.__class__, self).__iter__())

    @abc.abstractmethod
    def decrypt_keyblob(self, passphrase):
        if not self.s2k:
            # not encrypted
            return

        # Encryption/decryption of the secret data is done in CFB mode using
        # the key created from the passphrase and the Initial Vector from the
        # packet.  A different mode is used with V3 keys (which are only RSA)
        # than with other key formats.  (...)
        #
        # With V4 keys, a simpler method is used.  All secret MPI values are
        # encrypted in CFB mode, including the MPI bitcount prefix.

        # derive the session key from our passphrase, and then dereference passphrase
        sessionkey = self.s2k.derive_key(passphrase)
        del passphrase

        # attempt to decrypt this key
        pt = _decrypt(bytes(self.encbytes), bytes(sessionkey), self.s2k.encalg, bytes(self.s2k.iv))

        # check the hash to see if we decrypted successfully or not
        if self.s2k.usage == 254 and not pt[-20:] == hashlib.new('sha1', pt[:-20]).digest():
            # if the usage byte is 254, key material is followed by a 20-octet sha-1 hash of the rest
            # of the key material block
            raise PGPDecryptionError("Passphrase was incorrect!")

        if self.s2k.usage == 255 and not self.bytes_to_int(pt[-2:]) == (sum(bytearray(pt[:-2])) % 65536):
            # if the usage byte is 255, key material is followed by a 2-octet checksum of the rest
            # of the key material block
            raise PGPDecryptionError("Passphrase was incorrect!")

        return bytearray(pt)

    @abc.abstractmethod
    def clear(self):
        return False


class RSAPriv(PrivKey, RSAPub):
    def __init__(self):
        RSAPub.__init__(self)
        PrivKey.__init__(self)
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
        return rsa.RSAPrivateKey(
            p=self.p,
            q=self.q,
            private_exponent=self.d,
            dmp1=self.d % (self.p - 1),
            dmq1=self.d % (self.q - 1),
            iqmp=modinv(self.p, self.q),
            public_exponent=self.e,
            modulus=self.n
        )

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
        DSAPub.__init__(self)
        PrivKey.__init__(self)
        self.x = 0

    def __iter__(self):
        for i in DSAPub.__iter__(self):
            yield i
        yield self.x

    def __privkey__(self):
        return dsa.DSAPrivateKey(modulus=self.p,
                                 subgroup_order=self.q,
                                 generator=self.g,
                                 x=self.x,
                                 y=self.y)

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


class ElGPriv(PrivKey, ElGPub):
    def __init__(self):
        ElGPub.__init__(self)
        PrivKey.__init__(self)
        self.x = MPI(0)

    def __iter__(self):
        for i in ElGPub.__iter__(self):
            yield i
        yield self.x

    def __privkey__(self):
        raise NotImplementedError()

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


class CipherText(MPIs):
    def __bytes__(self):
        return b''.join(i.to_mpibytes() for i in self)

    @abc.abstractmethod
    def from_encrypter(self, ct):
        pass


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

    def __iter__(self):
        yield self.gk_mod_p
        yield self.myk_mod_p

    def parse(self, packet):
        self.gk_mod_p = MPI(packet)
        self.myk_mod_p = MPI(packet)

    def from_encrypter(self, ct):
        raise NotImplementedError()
