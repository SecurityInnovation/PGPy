""" subpacket.py
"""
import abc

from typing import Optional, Union

from ...constants import PacketType
from ...constants import SigSubpacketType
from ...constants import AttributeType

from ..types import VersionedHeader

from ...decorators import sdproperty

from ...types import Dispatchable
from ...types import Header as _Header

__all__ = ['Header',
           'EmbeddedSignatureHeader',
           'SubPacket',
           'Signature',
           'UserAttribute',
           'Opaque']


class Header(_Header):
    @sdproperty
    def critical(self) -> bool:
        return self._critical

    @critical.register
    def critical_bool(self, val: bool) -> None:
        self._critical = val

    @sdproperty
    def typeid(self) -> int:
        return self._typeid

    @typeid.register
    def typeid_int(self, val: int) -> None:
        self._typeid = val & 0x7f

    @typeid.register
    def typeid_bin(self, val: Union[bytes, bytearray]) -> None:
        v = self.bytes_to_int(val)
        self.typeid = v
        self.critical = bool(v & 0x80)

    def __init__(self) -> None:
        super().__init__()
        self._typeid = -1
        self.critical = False

    def parse(self, packet: bytearray) -> None:
        self.length = packet

        self.typeid = packet[:1]
        del packet[:1]

    def __len__(self) -> int:
        return self.llen + 1

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray(self.encode_length(self.length))
        _bytes += self.int_to_bytes((int(self.critical) << 7) + self.typeid)
        return _bytes


class EmbeddedSignatureHeader(VersionedHeader):
    def __bytearray__(self) -> bytearray:
        return bytearray([self.version])

    def parse(self, packet: bytearray) -> None:
        self.typeid = PacketType.Signature
        super().parse(packet)


class SubPacket(Dispatchable):
    __headercls__ = Header

    def __init__(self) -> None:
        super().__init__()
        self.header = Header()

        if (
            self.header.typeid == -1
            and (self.__typeid__ is not None)
        ):
            self.header.typeid = self.__typeid__

    def __bytearray__(self) -> bytearray:
        return self.header.__bytearray__()

    def __len__(self) -> int:
        return (self.header.llen + self.header.length)

    def __repr__(self) -> str:
        return "<{} [0x{:02x}] {}at 0x{:x}>".format(self.__class__.__name__, self.header.typeid, 'critical! ' if self.header.critical else '', id(self))

    def update_hlen(self) -> None:
        self.header.length = (len(self.__bytearray__()) - len(self.header)) + 1

    @abc.abstractmethod
    def parse(self, packet: bytearray) -> None:  # pragma: no cover
        if self.header._typeid == -1:
            self.header.parse(packet)


class Signature(SubPacket):
    __typeid__: Optional[SigSubpacketType] = None

    # allow one parameter for MetaDispatchable initialization:
    def __init__(self, _: Optional[bytes] = None) -> None:
        super().__init__()


class UserAttribute(SubPacket):
    __typeid__: Optional[AttributeType] = None

    # allow one parameter for MetaDispatchable initialization:
    def __init__(self, _: Optional[bytes] = None) -> None:
        super().__init__()


class Opaque(Signature, UserAttribute):
    __typeid__ = None

    @sdproperty
    def payload(self) -> bytearray:
        return self._payload

    @payload.register
    def payload_bin(self, val: Union[bytes, bytearray]) -> None:
        self._payload = bytearray(val)

    def __init__(self) -> None:
        super().__init__()
        self.payload = bytearray(b'')

    def __bytearray__(self) -> bytearray:
        _bytes = super().__bytearray__()
        _bytes += self.payload
        return _bytes

    def parse(self, packet: bytearray) -> None:
        super().parse(packet)
        self.payload = packet[:(self.header.length - 1)]
        del packet[:(self.header.length - 1)]
