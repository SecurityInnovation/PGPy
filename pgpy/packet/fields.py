""" fields.py
"""
import collections
import itertools
import re

from .subpackets import Signature
from .subpackets import UserAttribute

from .types import PubKey
from .types import Signature

from ..decorators import TypedProperty

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
            sp = Signature(packet)
            p += len(sp)
            self['h_' + sp.__class__.__name__] = sp

        self.unhashed_len = packet[:2]
        del packet[:2]

        p = 0
        while p < self.unhashed_len:
            sp = Signature(packet)
            p += len(sp)
            self[sp.__class__.__name__] = sp


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
