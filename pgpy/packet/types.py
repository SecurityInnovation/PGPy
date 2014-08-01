""" types.py
"""
import abc

from .fields import Header

from ..decorators import TypedProperty

from ..types import Dispatchable

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
        return "<{} [tag 0x{:02x} at 0x{:x}>".format(self.__class__.__name__, self.header.tag, id(self))

    @abc.abstractmethod
    def parse(self, packet):
        if self.header.tag == 0:
            self.header.parse(packet)


class VersionedPacket(Packet):
    @TypedProperty
    def version(self):
        return self._version
    @version.int
    def version(self, val):
        self._version = val
    @version.bytearray
    @version.bytes
    def version(self, val):
        self.version = self.bytes_to_int(val)


    def __init__(self):
        super(VersionedPacket, self).__init__(self)
        self.version = 4

    @abc.abstractmethod
    def parse(self, packet):
        super(VersionedPacket, self).parse(packet)
        self.version = packet[0]
        del packet[0]


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
        del packet[:self.header.length]