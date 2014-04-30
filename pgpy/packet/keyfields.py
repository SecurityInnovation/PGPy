""" keyfields.py
"""
import math
import collections
import hashlib
import functools

from .fields import Header, PacketField, PubKeyAlgo, HashAlgo, SymmetricKeyAlgo, PFIntEnum
from ..util import bytes_to_int, int_to_bytes


class MPIFields(object):
    field = {'name': "", 'bitlen': 0, 'bytes': b'', 'encoding': ''}

    # More metaprogramming, this time with a setter *and* a getter!
    def field_getter(self, item):
        if item not in self.fields.keys():
            self.fields[item] = self.field.copy()

        return self.fields[item]

    def field_setter(self, value, item, subitem=None):
        self.fields[item] = value

    for fname in ['md_mod_n', 'd', 'e', 'g', 'n', 'p', 'q', 'r', 's', 'u', 'x', 'y']:
        locals()[fname] = property(
            functools.partial(field_getter, item=fname),  # getter
            functools.partial(field_setter, item=fname),  # setter
        )

    def __init__(self):
        self.fields = collections.OrderedDict()
        self.encoding = ""

    def parse(self, packet, pktype, alg, sec=False):
        # determine fields
        if alg == PubKeyAlgo.RSAEncryptOrSign:
            self.encoding = 'PKCS-1'

            if pktype == Header.Tag.Signature:
                self.md_mod_n['name'] = 'RSA m^d mod n'

            if pktype in [Header.Tag.PubKey, Header.Tag.PubSubKey,
                          Header.Tag.PrivKey, Header.Tag.PrivSubKey] and not sec:
                self.n['name'] = 'RSA n'
                self.e['name'] = 'RSA e'

            if pktype in [Header.Tag.PrivKey, Header.Tag.PrivSubKey] and sec:
                self.d['name'] = 'RSA d'
                self.p['name'] = 'RSA p'
                self.q['name'] = 'RSA q'
                self.u['name'] = 'RSA u'

        if alg == PubKeyAlgo.DSA:
            self.encoding = 'hash(DSA q bits)'

            if pktype == Header.Tag.Signature:
                self.r['name'] = 'DSA r'
                self.s['name'] = 'DSA s'

            if pktype in [Header.Tag.PubKey, Header.Tag.PubSubKey,
                          Header.Tag.PrivKey, Header.Tag.PrivSubKey] and not sec:
                self.p['name'] = 'DSA p'
                self.q['name'] = 'DSA q'
                self.g['name'] = 'DSA g'
                self.y['name'] = 'DSA y'

            if pktype in [Header.Tag.PrivKey, Header.Tag.PrivSubKey] and sec:
                self.x['name'] = 'DSA x'

        if alg == PubKeyAlgo.ElGamal and not sec:
            self.p['name'] = 'ElGamal p'
            self.g['name'] = 'ElGamal g'
            self.y['name'] = 'ElGamal y'

        if alg == PubKeyAlgo.ElGamal and sec:
            self.x['name'] = 'ElGamal x'

        # if no fields were set, the combo requested has not yet been implemented
        if len(self.fields.keys()) == 0:
            raise NotImplementedError(alg.name)

        # now parse!
        pos = 0
        for i in range(0, len(self.fields.keys())):
            f = list(self.fields.keys())[i]
            self.fields[f]['bitlen'] = bytes_to_int(packet[pos:(pos + 2)])
            pos += 2

            length = int(math.ceil(self.fields[f]['bitlen'] / 8.0))
            mend = pos + length
            self.fields[f]['bytes'] = packet[pos:mend]
            pos = mend

    def __bytes__(self):
        _bytes = b''
        for field in self.fields.values():
            _bytes += int_to_bytes(field['bitlen'], 2)
            _bytes += field['bytes']

        return _bytes


class String2Key(PacketField):
    class Type(PFIntEnum):
        Simple = 0
        Salted = 1
        Iterated = 3

        def __str__(self):
            if self == String2Key.Type.Iterated:
                return "Iterated and salted string-to-key"

            ##TODO: the others
            raise NotImplementedError(self.name)

    def __init__(self, packet=None):
        self.id = 0
        self.alg = SymmetricKeyAlgo.Plaintext
        self.type = String2Key.Type.Simple
        self.hash = HashAlgo.Invalid
        self.salt = None
        self.c = None
        self.count = None
        self.iv = b''

        super(String2Key, self).__init__(packet)

    def parse(self, packet):
        self.id = bytes_to_int(packet[:1])
        pos = 1
        if self.id in [254, 255]:
            self.alg = SymmetricKeyAlgo(bytes_to_int(packet[1:2]))
            self.type = String2Key.Type(bytes_to_int(packet[2:3]))
            self.hash = HashAlgo(bytes_to_int(packet[3:4]))
            pos = 4

            if self.type in [String2Key.Type.Salted, String2Key.Type.Iterated]:
                self.salt = packet[4:12]
                pos = 12

            if self.type == String2Key.Type.Iterated:
                self.c = bytes_to_int(packet[12:13])
                self.count = (16 + (self.c & 15)) << ((self.c >> 4) + 6)
                pos = 13

        if self.id != 0:
            self.iv = packet[pos:(pos + int(self.alg.block_size() / 8))]

    def derive_key(self, passphrase):
        # we use the fields stored here along with the RFC 4880 String-to-Key usage description
        # to derive a symmetric key from the given passphrase.

        # how long does our key need to be, and how many hash contexts do we need?
        keylen = self.alg.keylen()
        hashlen = self.hash.digestlen()
        ctx = int(math.ceil(keylen / float(hashlen)))

        h = []
        # instantiate our hash context(s)
        for i in range(0, ctx):
            h.append(hashlib.new(self.hash.name, b'\x00' * i))

        # Simple S2K
        hsalt = ""
        hpass = passphrase.encode()

        # Salted S2K (or Iterated)
        if self.type in [String2Key.Type.Salted, String2Key.Type.Iterated]:
            hsalt = self.salt

        # Set the total to-be-hashed octet count
        count = len(self.salt + hpass)
        if self.type == String2Key.Type.Iterated and self.count > len(hsalt + hpass):
            count = self.count

        while count > len(self.salt + hpass):
            for hc in h:
                hc.update(hsalt)
                hc.update(hpass)
            count -= len(self.salt + hpass)

        if count > 0:
            for hc in h:
                hc.update((hsalt + hpass)[:count])

        return b''.join([hc.digest() for hc in h])[:int(keylen / 8)]

        # and finally, return!
        return digest

    def __bytes__(self):
        _bytes = b''
        _bytes += int_to_bytes(self.id)

        if self.id in [254, 255]:
            _bytes += int_to_bytes(self.alg.value)
            _bytes += int_to_bytes(self.type.value)
            _bytes += int_to_bytes(self.hash.value)

            if self.type in [String2Key.Type.Salted, String2Key.Type.Iterated]:
                _bytes += self.salt

            if self.type == String2Key.Type.Iterated:
                _bytes += int_to_bytes(self.c)

        if self.id != 0:
            _bytes += self.iv

        return _bytes