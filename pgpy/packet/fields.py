""" fields.py
"""
# Python 2.7 shenanigans
from __future__ import division

import abc
import collections
import hashlib
import itertools
import math
import re

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from .subpackets import Signature as SignatureSP
from .subpackets import UserAttribute

from .types import MPI

from ..constants import HashAlgorithm
from ..constants import String2KeyType
from ..constants import SymmetricKeyAlgorithm

from ..decorators import TypedProperty

from ..errors import PGPKeyDecryptionError
from ..errors import PGPOpenSSLCipherNotSupported

from ..types import Field


class SubPackets(collections.MutableMapping, Field):
    @TypedProperty
    def hashed_len(self):
        return self._hashed_len
    @hashed_len.int
    def hashed_len(self, val):
        self._hashed_len = val
    @hashed_len.bytearray
    @hashed_len.bytes
    def hashed_len(self, val):
        self.hashed_len = self.bytes_to_int(val)

    @TypedProperty
    def unhashed_len(self):
        return self._unhashed_len
    @unhashed_len.int
    def unhashed_len(self, val):
        self._unhashed_len = val
    @unhashed_len.bytearray
    @unhashed_len.bytes
    def unhashed_len(self, val):
        self.unhashed_len = self.bytes_to_int(val)

    def __init__(self):
        self._hashed_len = 0
        self._unhashed_len = 0
        self.__hashed_sp = collections.OrderedDict()
        self.__unhashed_sp = collections.OrderedDict()

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += self.int_to_bytes(self.hashed_len, 2)
        for hsp in self.__hashed_sp.values():
            _bytes += hsp.__bytes__()
        _bytes += self.int_to_bytes(self.unhashed_len, 2)
        for uhsp in self.__unhashed_sp.values():
            _bytes += uhsp.__bytes__()
        return bytes(_bytes)

    def __len__(self):
        return self.hashed_len + self.unhashed_len + 4

    def __iter__(self):
        for sp in itertools.chain(self.__hashed_sp, self.__unhashed_sp):
            yield sp

    def __setitem__(self, key, val):
        # the key provided should always be the classname for the subpacket
        # but, there can be multiple subpackets of the same type
        # so, it should be stored in the format: [h_]<key>_<seqid>
        # where:
        #  - <key> is the classname of val
        #  - <seqid> is a sequence id, starting at 0, for a given classname
        if not re.match(r'^.*_[0-9]', key):
            i = 0
            while '{:s}_{:d}'.format(key, i) in self:
                i += 1
            key = '{:s}_{:d}'.format(key, i)

        if key.startswith('h_'):
            self.__hashed_sp[key[2:]] = val

        else:
            self.__unhashed_sp[key] = val

    def __getitem__(self, key):
        if not re.match(r'^.*_[0-9]', key):
            if key.startswith('h_'):
                return [v for k, v in self.__hashed_sp.items() if key[2:] in k]

            else:
                return [v for k, v in self.__unhashed_sp. items() if key in k]

    def __delitem__(self, key):
        ##TODO: this
        pass

    def __contains__(self, key):
        return any([key in self.__hashed_sp, key in self.__unhashed_sp])

    def parse(self, packet):
        self.hashed_len = packet[:2]
        del packet[:2]

        p = 0
        while p < self.hashed_len:
            sp = SignatureSP(packet)
            p += len(sp)
            self['h_' + sp.__class__.__name__] = sp

        self.unhashed_len = packet[:2]
        del packet[:2]

        p = 0
        while p < self.unhashed_len:
            sp = SignatureSP(packet)
            p += len(sp)
            self[sp.__class__.__name__] = sp


class Signature(MPI):
    pass


class RSASignature(Signature):
    def __init__(self):
        self.md_mod_n = bytearray()

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += self.encode_mpi(self.md_mod_n)
        return _bytes

    def __len__(self):
        return len(self.md_mod_n) + 2

    def parse(self, packet):
        self.md_mod_n = self.decode_mpi(packet)


class DSASignature(Signature):
    def __init__(self):
        # super(DSASignature, self).__init__()
        self.r = bytearray()
        self.s = bytearray()

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += self.encode_mpi(self.r)
        _bytes += self.encode_mpi(self.s)
        return bytes(_bytes)

    def __len__(self):
        return len(self.r + self.s) + 4

    def parse(self, packet):
        self.r = self.decode_mpi(packet)
        self.s = self.decode_mpi(packet)


class PubKey(MPI):
    pass


class RSAPub(PubKey):
    def __init__(self):
        # super(RSAPub, self).__init__()
        self.n = bytearray()
        self.e = bytearray()

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += self.encode_mpi(self.n)
        _bytes += self.encode_mpi(self.e)
        return bytes(_bytes)

    def __len__(self):
        return len(self.n + self.e) + 4

    def parse(self, packet):
        self.n = self.decode_mpi(packet)
        self.e = self.decode_mpi(packet)


class DSAPub(PubKey):
    def __init__(self):
        self.p = bytearray()
        self.q = bytearray()
        self.g = bytearray()
        self.y = bytearray()

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += self.encode_mpi(self.p)
        _bytes += self.encode_mpi(self.q)
        _bytes += self.encode_mpi(self.g)
        _bytes += self.encode_mpi(self.y)
        return bytes(_bytes)

    def __len__(self):
        return len(self.p + self.q + self.g + self.y) + 8

    def parse(self, packet):
        self.p = self.decode_mpi(packet)
        self.q = self.decode_mpi(packet)
        self.g = self.decode_mpi(packet)
        self.y = self.decode_mpi(packet)


class ElGPub(PubKey):
    def __init__(self):
        self.p = bytearray()
        self.g = bytearray()
        self.y = bytearray()

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += self.encode_mpi(self.p)
        _bytes += self.encode_mpi(self.g)
        _bytes += self.encode_mpi(self.y)
        return bytes(_bytes)

    def __len__(self):
        return len(self.p + self.g + self.y) + 6

    def parse(self, packet):
        self.p = self.decode_mpi(packet)
        self.g = self.decode_mpi(packet)
        self.y = self.decode_mpi(packet)


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
            _bytes += self.iv
        return bytes(_bytes)

    def __len__(self):
        return len(bytes(self))

    def __bool__(self):
        return self.usage in [254, 255]

    # Python 2.7 shenanigans
    def __nonzero__(self):
        return self.usage in [254, 255]

    def parse(self, packet):
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
        _bytes = bytearray()
        _bytes += self.s2k.__bytes__()
        if self.s2k:
            _bytes += self.encbytes
        return bytes(_bytes)

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
        cipher = Cipher(self.s2k.encalg.cipher(bytes(sessionkey)), modes.CFB(bytes(self.s2k.iv)), backend=default_backend())
        del sessionkey

        try:
            decryptor = cipher.decryptor()

        except UnsupportedAlgorithm as e:
            raise PGPOpenSSLCipherNotSupported from e

        pt = decryptor.update(bytes(self.encbytes)) + decryptor.finalize()

        # check the hash to see if we decrypted successfully or not
        if self.s2k.usage == 254 and not pt[-20:] == hashlib.new('sha1', pt[:-20]).digest():
            # if the usage byte is 254, key material is followed by a 20-octet sha-1 hash of the rest
            # of the key material block
            raise PGPKeyDecryptionError("Passphrase was incorrect!")

        if self.s2k.usage == 255 and not self.bytes_to_int(pt[-2:]) == (sum(bytearray(pt[:-2])) % 65536):
            # if the usage byte is 255, key material is followed by a 2-octet checksum of the rest
            # of the key material block
            raise PGPKeyDecryptionError("Passphrase was incorrect!")

        return bytearray(pt)


class RSAPriv(PrivKey):
    def __init__(self):
        super(RSAPriv, self).__init__()
        self.d = bytearray()
        self.p = bytearray()
        self.q = bytearray()
        self.u = bytearray()

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += super(RSAPriv, self).__bytes__()

        if not self.s2k:
            _bytes += self.encode_mpi(self.d)
            _bytes += self.encode_mpi(self.p)
            _bytes += self.encode_mpi(self.q)
            _bytes += self.encode_mpi(self.u)

            if self.s2k.usage == 0:
                _bytes += self.chksum

        return bytes(_bytes)

    def __len__(self):
        return len(self.s2k) + len(self.d + self.p + self.q + self.u) + 8

    def parse(self, packet):
        self.s2k.parse(packet)

        if not self.s2k:
            self.d = self.decode_mpi(packet)
            self.p = self.decode_mpi(packet)
            self.q = self.decode_mpi(packet)
            self.u = self.decode_mpi(packet)

            if self.s2k.usage == 0:
                self.chksum = packet[:2]
                del packet[:2]

        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

    def decrypt_keyblob(self, passphrase):
        kb = super(RSAPriv, self).decrypt_keyblob(passphrase)
        del passphrase

        self.d = self.decode_mpi(kb)
        self.p = self.decode_mpi(kb)
        self.q = self.decode_mpi(kb)
        self.u = self.decode_mpi(kb)

        if self.s2k.usage in [254, 255]:
            self.chksum = kb
            del kb


class DSAPriv(PrivKey):
    def __init__(self):
        super(DSAPriv, self).__init__()
        self.x = bytearray()

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += super(DSAPriv, self).__bytes__()

        if not self.s2k:
            _bytes += self.encode_mpi(self.x)

            if self.s2k.usage == 0:
                _bytes += self.chksum

        return bytes(_bytes)

    def __len__(self):
        return len(self.s2k) + len(self.encbytes) if self.s2k else len(self.x) + 2

    def parse(self, packet):
        self.s2k.parse(packet)

        if not self.s2k:
            self.x = self.decode_mpi(packet)

        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

        if self.s2k.usage in [0, 255]:
            self.chksum = packet[:2]
            del packet[:2]

    def decrypt_keyblob(self, passphrase):
        kb = super(DSAPriv, self).decrypt_keyblob(passphrase)
        del passphrase

        self.x = self.decode_mpi(kb)

        if self.s2k.usage in [254, 255]:
            self.chksum = kb
            del kb


class ElGPriv(DSAPriv):
    pass
