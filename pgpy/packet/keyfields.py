""" keyfields.py
"""
import math
import collections
import copy

from .fields import Header, PacketField, PubKeyAlgo, HashAlgo, SymmetricKeyAlgo, PFIntEnum
from ..util import bytes_to_int, int_to_bytes

class MPIFields(object):
    field = {'name': "", 'bitlen': 0, 'bytes': b'', 'encoding': ''}

    def __init__(self):
        self.fields = collections.OrderedDict()
        self.encoding = ""

    def parse(self, packet, pktype, alg, sec=False):
        # determine fields
        if alg == PubKeyAlgo.RSAEncryptOrSign:
            self.encoding = 'PKCS-1'

            if pktype == Header.Tag.Signature:
                self.fields['md_mod_n'] = copy.copy(self.field)
                self.md_mod_n['name'] = 'RSA m^d mod n'

            if pktype in [Header.Tag.PubKey, Header.Tag.PubSubKey,
                          Header.Tag.PrivKey, Header.Tag.PrivSubKey] and not sec:
                self.fields['n'] = copy.copy(self.field)
                self.n['name'] = 'RSA n'

                self.fields['e'] = copy.copy(self.field)
                self.e['name'] = 'RSA e'

            if pktype in [Header.Tag.PrivKey, Header.Tag.PrivSubKey] and sec:
                self.fields['d'] = copy.copy(self.field)
                self.d['name'] = 'RSA d'

                self.fields['p'] = copy.copy(self.field)
                self.p['name'] = 'RSA p'

                self.fields['q'] = copy.copy(self.field)
                self.q['name'] = 'RSA q'

                self.fields['u'] = copy.copy(self.field)
                self.u['name'] = 'RSA u'

        if alg == PubKeyAlgo.DSA:
            self.encoding = 'hash(DSA q bits)'

            if pktype == Header.Tag.Signature:
                self.fields['dsa_r'] = copy.copy(self.field)
                self.dsa_r['name'] = 'DSA r'

                self.fields['dsa_s'] = copy.copy(self.field)
                self.dsa_s['name'] = 'DSA s'

            if pktype in [Header.Tag.PubKey, Header.Tag.PubSubKey,
                          Header.Tag.PrivKey, Header.Tag.PrivSubKey] and not sec:
                self.fields['dsa_p'] = copy.copy(self.field)
                self.dsa_p['name'] = 'DSA p'

                self.fields['dsa_q'] = copy.copy(self.field)
                self.dsa_q['name'] = 'DSA q'

                self.fields['dsa_g'] = copy.copy(self.field)
                self.dsa_g['name'] = 'DSA g'

                self.fields['dsa_y'] = copy.copy(self.field)
                self.dsa_y['name'] = 'DSA y'

            if pktype in [Header.Tag.PrivKey, Header.Tag.PrivSubKey] and sec:
                self.fields['dsa_x'] = copy.copy(self.field)
                self.dsa_x['name'] = 'DSA x'

        if alg == PubKeyAlgo.ElGamal and not sec:
            self.fields['ElGamal_p'] = copy.copy(self.field)
            self.ElGamal_p['name'] = 'ElGamal p'

            self.fields['ElGamal_g'] = copy.copy(self.field)
            self.ElGamal_g['name'] = 'ElGamal g'

            self.fields['ElGamal_y'] = copy.copy(self.field)
            self.ElGamal_y['name'] = 'ElGamal y'

        if alg == PubKeyAlgo.ElGamal and sec:
            self.fields['ElGamal_x'] = copy.copy(self.field)
            self.ElGamal_x['name'] = 'ElGamal x'

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


    def __getattr__(self, item):
        return self.fields[item]

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
        self.hash = 0
        self.salt = None
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
                self.salt = packet[4:11]
                pos = 11

            if self.type == String2Key.Type.Iterated:
                c = bytes_to_int(packet[11:12])
                self.count = (16 + (c & 15)) << ((c >> 4) + 6)
                pos = 12

        if self.id != 0:
            self.iv = packet[pos:(pos + int(self.alg.block_size()/8))]

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
                for c in range(0, 255):
                    cnt = (16 + (c & 15)) << ((c >> 4) + 6)
                    if cnt == self.count:
                        _bytes += int_to_bytes(c)
                        break

        if self.id != 0:
            _bytes += self.iv

        return _bytes