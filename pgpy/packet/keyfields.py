""" keyfields.py
"""
import math
import collections
import hashlib
import functools

from . import PubKeyAlgo, HashAlgo, SymmetricKeyAlgo
from .types import PFIntEnum
from .fields import Header, PacketField
from ..util import bytes_to_int, int_to_bytes


class MPIFields(object):
    field = {'name': "", 'bitlen': 0, 'bytes': b''}

    @property
    def empty(self):
        return not any([f['bitlen'] > 0 for f in self.fields.values()])

    @property
    def as_asn1_der(self):
        # turn filled in values in self.fields into an ASN.1 sequence of integers
        # (see http://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One#Example_encoded_in_DER)
        # type tag indicating that this is a SEQUENCE
        _bytes = b'\x30'
        # next is the constructed length of all integer fields, so construct those first
        _fbytes = b''
        for item in [ f['bytes'] for f in self.fields.values() if f['name'] != '' ]:
            # field type is INTEGER, so this is 0x02
            _fbytes += b'\x02'

            # length in octets of this field
            if len(item) > 128:
                # long form
                _fbytes += int_to_bytes(128 ^ len(int_to_bytes(len(item))))
            _fbytes += int_to_bytes(len(item))

            # and the field itself
            _fbytes += item

        # now add the length of _fbytes to _bytes
        if len(_fbytes) > 128:
            # long form
            _bytes += int_to_bytes(128 ^ len(int_to_bytes(len(_fbytes))))
        _bytes += int_to_bytes(len(_fbytes))

        # and finally _fbytes
        _bytes += _fbytes

        return _bytes

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

    def reset(self):
        import ctypes
        import sys

        for k in self.fields.keys():
            # write null bytes over the key field bytes
            bufsize = len(self.fields[k]['bytes'])
            offset = sys.getsizeof(self.fields[k]['bytes']) - (bufsize + 1)
            ctypes.memset(id(self.fields[k]['bytes']) + offset, 0, bufsize)

            # set bit length to 0
            self.fields[k]['bitlen'] = 0

        del self.fields
        self.fields = collections.OrderedDict()


class String2Key(PacketField):
    class Type(PFIntEnum):
        Simple = 0
        Salted = 1
        Iterated = 3

        def __str__(self):
            if self == String2Key.Type.Simple:
                return "Simple string-to-key"

            if self == String2Key.Type.Salted:
                return "Salted string-to-key"

            if self == String2Key.Type.Iterated:
                return "Iterated and salted string-to-key"

            raise NotImplementedError(self.name)  # pragma: no cover

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
            self.iv = packet[pos:(pos + int(self.alg.block_size / 8))]

    def derive_key(self, passphrase):
        # we use the fields stored here along with the RFC 4880 String-to-Key usage description
        # to derive a symmetric key from the given passphrase.

        # how long does our key need to be, and how many hash contexts do we need?
        keylen = self.alg.keylen
        hashlen = self.hash.digestlen
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

        # and finally, return!
        return b''.join([hc.digest() for hc in h])[:int(keylen / 8)]

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