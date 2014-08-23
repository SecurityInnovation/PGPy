""" types.py
"""
from __future__ import division

import abc

import six

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

        if (self._lenfmt == 0 and self.llen > 0) or self._lenfmt == 1:
            self.length = packet

        else:
            # indeterminate packet length
            self.length = len(packet)


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
        self.header = self.__headercls__()

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
        return "<{cls:s} [tag 0x{tag:02d}][v{ver:d}] at 0x{id:x}>".format(cls=self.__class__.__name__, tag=self.header.tag,
                                                                          ver=self.header.version, id=id(self))


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
        pend = self.header.length
        if hasattr(self.header, 'version'):
            pend -= 1

        self.payload = packet[:pend]
        del packet[:pend]


# key marker classes for convenience
class Key(object):
    pass


class Public(Key):
    pass


class Private(Key):
    pass


class Primary(Key):
    pass


class Sub(Key):
    pass


# Python 2.7 shenanigans
if six.PY3:
    long = int


class MPI(long):
    def __new__(cls, num):
        mpi = num
        if isinstance(num, (bytes, bytearray)):
            fl = ((MPIs.bytes_to_int(num[:2]) + 7) // 8)
            del num[:2]

            mpi = MPIs.bytes_to_int(num[:fl])
            del num[:fl]

        return super(MPI, cls).__new__(cls, mpi)

    def byte_length(self):
        return ((self.bit_length() + 7) // 8)

    def to_mpibytes(self):
        return MPIs.int_to_bytes(self.bit_length(), 2) + MPIs.int_to_bytes(self, self.byte_length())

    def __len__(self):
        return self.byte_length() + 2


class MPIs(Field):
    # this differs from MPI in that its' subclasses hold/parse several MPI fields
    # and, in the case of v4 private keys, also a String2Key specifier/information.
    def __len__(self):
        return sum(len(i) for i in self)

    @abc.abstractmethod
    def __iter__(self):
        yield None
