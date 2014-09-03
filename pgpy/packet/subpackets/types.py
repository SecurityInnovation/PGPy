""" subpacket.py
"""
import abc

from ..types import VersionedHeader

from ...decorators import TypedProperty
from ...types import Dispatchable
from ...types import Header as _Header


class Header(_Header):
    @TypedProperty
    def critical(self):
        return self._critical

    @critical.bool
    def critical(self, val):
        self._critical = val

    @TypedProperty
    def typeid(self):
        return self._typeid

    @typeid.int
    def typeid(self, val):
        self._typeid = val & 0x7f

    @typeid.bytearray
    @typeid.bytes
    def typeid(self, val):
        v = self.bytes_to_int(val)
        self.typeid = v
        self.critical = bool(v & 0x80)

    def __init__(self):
        super(Header, self).__init__()
        self.typeid = b'\x00'
        self.critical = False

    def parse(self, packet):
        self.length = packet

        self.typeid = packet[:1]
        del packet[:1]

    def __len__(self):
        return self.llen + 1

    def __bytes__(self):
        _bytes = self.encode_length(self.length)
        _bytes += self.int_to_bytes((int(self.critical) << 7) + self.typeid)
        return _bytes


class EmbeddedSignatureHeader(VersionedHeader):
    def __bytes__(self):
        _bytes = bytearray()
        _bytes.append(self.version)
        return bytes(_bytes)

    def parse(self, packet):
        self.tag = 2
        super(EmbeddedSignatureHeader, self).parse(packet)


class SubPacket(Dispatchable):
    __headercls__ = Header

    def __init__(self):
        super(SubPacket, self).__init__()
        self.header = Header()

        # if self.__typeid__ not in [-1, None]:
        if (self.header.typeid == 0x00
                and (not hasattr(self.__typeid__, '__abstractmethod__'))
                and (self.__typeid__ not in [-1, None])):
            self.header.typeid = self.__typeid__

    def __bytes__(self):
        return self.header.__bytes__()

    def __len__(self):
        return (self.header.llen + self.header.length)

    def __repr__(self):
        return "<{} [0x{:02x}] at 0x{:x}>".format(self.__class__.__name__, self.header.typeid, id(self))

    def update_hlen(self):
        self.header.length = (len(self.__bytes__()) - len(self.header)) + 1

    @abc.abstractmethod  # subclasses still need to specify this
    def parse(self, packet):
        if self.header._typeid == 0:
            self.header.parse(packet)


class Signature(SubPacket):
    __typeid__ = -1


class UserAttribute(SubPacket):
    __typeid__ = -1


class Opaque(Signature, UserAttribute):
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
        self.payload = packet[:(self.header.length - 1)]
        del packet[:(self.header.length - 1)]
