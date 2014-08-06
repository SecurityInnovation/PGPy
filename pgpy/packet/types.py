""" types.py
"""
from __future__ import division

import abc

from ..decorators import TypedProperty

from ..types import Dispatchable
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


class Packet(Dispatchable):
    __typeid__ = -1
    __headercls__ = Header

    def __init__(self):
        super(Packet, self).__init__()
        self.header = Header()

    @abc.abstractmethod
    def __bytes__(self):
        return self.header.__bytes__()

    def __len__(self):
        return len(self.header) + self.header.length

    def __repr__(self):
        return "<{cls:s} [tag 0x{tag:02d}] at 0x{id:x}>".format(cls=self.__class__.__name__, tag=self.header.tag, id=id(self))

    @abc.abstractmethod
    def parse(self, packet):
        if self.header.tag == 0:
            self.header.parse(packet)


class VersionedPacket(Packet):
    __headercls__ = VersionedHeader
    def __repr__(self):
        return "<{cls:s} [tag 0x{tag:02d}][v{ver:d}] at 0x{id:x}>".format(cls=self.__class__.__name__, tag=self.header.tag, ver=self.header.version, id=id(self))


class Opaque(Packet):
    __typeid__ = None

    @TypedProperty
    def payload(self):
        return self._payload
    @payload.bytearray
    @payload.bytes
    def payload(self, val):
        self._payload = val

    def __init__(self):
        super(Opaque, self).__init__()
        self.payload = b''

    def __bytes__(self):
        _bytes = super(Opaque, self).__bytes__()
        _bytes += self.payload
        return _bytes

    def parse(self, packet):
        super(Opaque, self).parse(packet)
        self.payload = packet[:self.header.length]
        del packet[:self.header.length if not hasattr(self.header, 'version') else (self.header.length - 1)]


class MPI(Field):
    @staticmethod
    def encode_mpi(d):
        _bytes = bytearray()
        di = MPI.bytes_to_int(d)
        _bytes += MPI.int_to_bytes(di.bit_length(), 2)
        _bytes += MPI.int_to_bytes(di, ((di.bit_length() + 7) // 8))
        return _bytes

    @staticmethod
    def decode_mpi(packet):
        fl = (MPI.bytes_to_int(packet[:2]) + 7) // 8
        del packet[:2]

        mpi = packet[:fl]
        del packet[:fl]

        return mpi
