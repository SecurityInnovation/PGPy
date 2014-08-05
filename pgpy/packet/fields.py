""" fields.py
"""
import collections
import itertools
import re

from .subpackets import Signature
from .subpackets import UserAttribute

from ..decorators import TypedProperty

from ..types import Field
from ..types import Header as _Header


class Header(_Header):
    @TypedProperty
    def tag(self):
        return self._tag
    @tag.int
    def tag(self, val):
        self._tag = (val & 0x3F) if self._lenfmt else ((val & 0x3C) >> 2)

    @property
    def typeid(self):
        return self.tag

    def __init__(self):
        super(Header, self).__init__()
        self.tag = 0x00

    def __bytes__(self):
        tag = 0x80 | (self._lenfmt << 6)
        tag |= (self.tag) if self._lenfmt else ((self.tag << 2) | {1: 0, 2: 1, 4: 2, 0: 3}[self.llen])

        _bytes = self.int_to_bytes(tag)
        _bytes += self.encode_length(self.length, self._lenfmt, self.llen)
        return _bytes

    def __len__(self):
        return 1 + self.llen

    def parse(self, packet):
        """
        There are two formats for headers

        old style
        ---------

        Old style headers can be 1, 2, 3, or 6 octets long and are composed of a Tag and a Length.
        If the header length is 1 octet (length_type == 3), then there is no Length field.

        new style
        ---------

        New style headers can be 2, 3, or 6 octets long and are also composed of a Tag and a Length.


        Packet Tag
        ----------

        The packet tag is the first byte, comprising the following fields:

        +-------------+----------+---------------+---+---+---+---+----------+----------+
        | byte        | 1                                                              |
        +-------------+----------+---------------+---+---+---+---+----------+----------+
        | bit         | 7        | 6             | 5 | 4 | 3 | 2 | 1        | 0        |
        +-------------+----------+---------------+---+---+---+---+----------+----------+
        | old-style   | always 1 | packet format | packet tag    | length type         |
        | description |          | 0 = old-style |               | 0 = 1 octet         |
        |             |          | 1 = new-style |               | 1 = 2 octets        |
        |             |          |               |               | 2 = 5 octets        |
        |             |          |               |               | 3 = no length field |
        +-------------+          +               +---------------+---------------------+
        | new-style   |          |               | packet tag                          |
        | description |          |               |                                     |
        +-------------+----------+---------------+-------------------------------------+

        :param packet: raw packet bytes
        """
        self._lenfmt = ((packet[0] & 0x40) >> 6)
        self.tag = packet[0]
        if self._lenfmt == 0:
            self.llen = (packet[0] & 0x03)
        del packet[0]

        self.length = packet
        del packet[:self.llen]


class VersionedHeader(Header):
    @TypedProperty
    def version(self):
        return self._version
    @version.int
    def version(self, val):
        self._version = val

    def __init__(self):
        super(VersionedHeader, self).__init__()
        self.version = 0

    def __bytes__(self):
        _bytes = bytearray(super(VersionedHeader, self).__bytes__())
        _bytes.append(self.version)
        return bytes(_bytes)

    def parse(self, packet):
        if self.tag == 0:
            super(VersionedHeader, self).parse(packet)

        if self.version == 0:
            self.version = packet[0]
            del packet[0]


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



# class Header(PacketField):
#     class Format(IntEnum):
#         old = 0
#         new = 1
#
#     class Tag(IntEnum):
#         ##TODO: add the rest of these
#         Invalid = 0
#         Signature = 2
#         PrivKey = 5
#         PrivSubKey = 7
#         PubKey = 6
#         Trust = 12
#         UserID = 13
#         PubSubKey = 14
#         UserAttribute = 17
#
#     class LengthType(IntEnum):
#         One = 0x0
#         Two = 0x1
#         Four = 0x2
#         Indeterminate = 0x3
#
#         def __len__(self):
#             lens = {Header.LengthType.One: 1,
#                     Header.LengthType.Two: 2,
#                     Header.LengthType.Four: 4,
#                     Header.LengthType.Indeterminate: 0}
#
#             return lens[self]
#
#     @property
#     def aways_1(self):
#         return self._tag >> 7
#
#     @property
#     def format(self):
#         return Header.Format((self._tag & 0x40) >> 6)
#
#     @property
#     def tag(self):
#         ##TODO: check if the tag matches the parent packet; if not, set it appropriately
#         if self.format == Header.Format.old:
#             return Header.Tag((self._tag & 0x3C) >> 2)
#
#         if self.format == Header.Format.new:
#             return Header.Tag(self._tag & 0x3F)
#
#     @tag.setter
#     def tag(self, value):
#         ##TODO: set tag values when not parsing
#         if type(value) is int:
#             if (value >> 7) != 1:
#                 raise PGPError("Malformed tag!")
#
#             self._tag = value
#
#             if self.tag == Header.Tag.Invalid:
#                 raise PGPError("Invalid tag!")
#
#     @property
#     def length_type(self):
#         if self.format == Header.Format.old:
#             ##TODO: calculate length type based on calculated length
#             if self._parent is None:
#                 return Header.LengthType(self._tag & 0x03)
#         return None
#
#     @property
#     def length(self):
#         if self._parent is None:
#             return self._length
#
#         ##TODO: calculate length from the parent packet
#         return 0
#
#     @length.setter
#     def length(self, value):
#         # sanity checking
#         if value < 0:
#             raise ValueError(value)
#
#         if self.format == Header.Format.old:
#             lt = self.length_type
#
#             if lt == Header.LengthType.One and value > 0xFF:
#                 raise ValueError(value)
#
#             if lt == Header.LengthType.Two and value > 0xFFFF:
#                 raise ValueError(value)
#
#             if lt == Header.LengthType.Four and value > 0xFFFFFF:
#                 raise ValueError(value)
#
#         self._length = value
#
#     def __init__(self):
#         # 0x80 sets the first bit to 1 for the always_1 field
#         # 0x40 is format identifier new
#         # 0x80 + 0x40 = 0xC0
#         self._tag = 0xC0
#
#         # self._length_type = 0
#         self._length = 0
#         self._parent = None
#
#     def parse(self, packet):

#
#         # parse the full tag, including length_type if this is an old-format packet header
#         self.tag = bytes_to_int(packet[:1])
#         packet = packet[1:]
#
#         if self.format == Header.Format.old:
#             self.length = bytes_to_int(packet[:len(self.length_type)])
#             packet = packet[len(self.length_type):]
#
#         if self.format == Header.Format.new:
#             fo = bytes_to_int(packet[:1])
#
#             # 1 octet length
#             if fo < 191:
#                 self.length = bytes_to_int(packet[:1])
#                 packet = packet[1:]
#
#             # 2 octet length
#             elif 223 > fo > 191:
#                 self.length = bytes_to_int(packet[:2])
#                 packet = packet[2:]
#
#             # 5 octet length
#             elif fo == 255:
#                 self.length = bytes_to_int(packet[1:5])
#                 packet = packet[5:]
#
#             else:
#                 raise PGPError("Malformed length!")
#
#         return packet
#
#     def __bytes__(self):
#         _bytes = b''
#         _bytes += int_to_bytes(self._tag)
#
#         # old header format
#         if self.format == Header.Format.old:
#             if self.length_type != Header.LengthType.Indeterminate:
#                 _bytes += int_to_bytes(self.length)
#
#         # new header format
#         else:
#             # 1 octet length
#             if self.length < 192:
#                 _bytes += int_to_bytes(self.length)
#
#             # 2 octet length
#             elif self.length < 8384:
#                 _bytes += int_to_bytes(((self.length & 0xFF00) + (192 << 8)) + ((self.length & 0xFF) - 192), 2)
#
#             # 5 octet length
#             else:
#                 _bytes += b'\xFF' + int_to_bytes(self.length, 4)
#
#         return _bytes
#
#     def __pgpdump__(self):
#         raise NotImplementedError()
# class SignatureSubPackets(PacketField):
#     def __init__(self):
#         self.length = 0
#         self.hashed = False
#         self.subpackets = []
#
#     def parse(self, packet):
#         self.length = bytes_to_int(packet[0:2])
#         packet = packet[2:]
#
#         while sum([len(sp.__bytes__()) for sp in self.subpackets]) < self.length:
#             sp = SignatureSubPacket(packet)
#             self.subpackets.append(sp)
#
#             if sp.__class__.__name__ == "OpaqueSubPacket":
#                 a=0
#
#             llen = len(sp.__bytes__())
#             packet = packet[llen:]
#
#         return packet
#         # while pos < self.length:
#         #     sp = SigSubPacket(packet[pos:])
#         #     self.subpackets.append(sp)
#         #     pos += sp.length
#         #     if 192 > sp.length:
#         #         pos += 1
#         #
#         #     elif 255 > sp.length >= 192:
#         #         pos += 2
#         #
#         #     else:
#         #         pos += 5
#
#     def __bytes__(self):
#         _bytes = int_to_bytes(self.length, 2)
#
#         for subpacket in self.subpackets:
#             _bytes += subpacket.__bytes__()
#
#         return _bytes
#
#     def __pgpdump__(self):
#         raise NotImplementedError()


# class UserAttributeSubPackets(PacketField):
#     def __init__(self, packet=None):
#         super(UserAttributeSubPackets, self).__init__()
#         self.subpackets = []
#
#     def parse(self, packet):
#         self.subpackets.append(UASubPacket(packet))
#         return packet[len(self.subpackets[-1].__bytes__()):]
#
#     def __bytes__(self):
#         _bytes = b''
#         for sp in self.subpackets:
#             _bytes += sp.__bytes__()
#
#         return _bytes
#
#     def __pgpdump__(self):
#         raise NotImplementedError()
