""" types.py
"""
import abc

from .fields import Header
from .fields import VersionedHeader

from ..decorators import TypedProperty

from ..types import Dispatchable
from ..types import Field


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
    pass


class Signature(MPI):
    pass


class PubKey(MPI):
    pass


class PrivKey(PubKey):
    pass
