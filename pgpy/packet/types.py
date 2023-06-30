""" types.py
"""

import abc
import copy

from typing import Iterator, Optional, Tuple, Type, Union

from ..constants import PacketType

from ..decorators import sdproperty

from ..types import DispatchGuidance
from ..types import Dispatchable
from ..types import Field
from ..types import Header as _Header

from ..constants import PubKeyAlgorithm

__all__ = ['Header',
           'VersionedHeader',
           'Packet',
           'VersionedPacket',
           'Opaque',
           'Key',
           'Public',
           'Private',
           'Primary',
           'Sub',
           'MPI',
           'MPIs', ]


class Header(_Header):
    @sdproperty
    def typeid(self) -> PacketType:
        return self._typeid

    @typeid.register
    def typeid_int(self, val: int) -> None:
        if isinstance(val, PacketType):
            self._typeid = val
            return

        if self._openpgp_format:
            type_id = (val & 0x3F)
        else:
            type_id = ((val & 0x3C) >> 2)

        self._typeid = PacketType(type_id)
        if self._typeid is PacketType.Unknown:
            self._opaque_typeid = type_id

    def __init__(self) -> None:
        super().__init__()
        self._typeid = PacketType.Invalid

    def __bytearray__(self) -> bytearray:
        tag = 0x80 | (0x40 if self._openpgp_format else 0x00)
        tval: int = self._opaque_typeid if self._typeid is PacketType.Unknown else self._typeid
        tag |= (tval) if self._openpgp_format else ((tval << 2) | {1: 0, 2: 1, 4: 2, 0: 3}[self.llen])

        _bytes = bytearray([tag])
        _bytes += self.encode_length(self.length, self._openpgp_format, self.llen)
        return _bytes

    def __len__(self) -> int:
        return 1 + self.llen

    def parse(self, packet: bytearray) -> None:
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
        self._openpgp_format = bool(packet[0] & 0x40)
        self.typeid = packet[0]
        if not self._openpgp_format:
            self.llen = (packet[0] & 0x03)
        del packet[0]

        if (not self._openpgp_format and self.llen > 0) or self._openpgp_format:
            self.length = packet

        else:
            # indeterminate packet length
            self.length = len(packet)


class VersionedHeader(Header):
    @sdproperty
    def version(self) -> int:
        return self._version

    @version.register
    def version_int(self, val: int) -> None:
        self._version = val

    def __init__(self) -> None:
        super().__init__()
        self.version = 0

    def __bytearray__(self) -> bytearray:
        _bytes = bytearray(super().__bytearray__())
        _bytes += bytearray([self.version])
        return _bytes

    def parse(self, packet: bytearray) -> None:  # pragma: no cover
        if self.typeid is PacketType.Invalid:
            super().parse(packet)

        if self.version == 0:
            self.version = packet[0]
            del packet[0]


class Packet(Dispatchable):
    __typeid__: Optional[Union[PacketType, DispatchGuidance]] = None
    __headercls__: Type[Header] = Header

    def __init__(self, _=None) -> None:
        super().__init__()
        self.header = self.__headercls__()
        if isinstance(self.__typeid__, int):
            self.header.typeid = self.__typeid__

    @abc.abstractmethod
    def __bytearray__(self) -> bytearray:
        return self.header.__bytearray__()

    def __len__(self) -> int:
        return len(self.header) + self.header.length

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} [type {self.header.typeid:02}] at 0x{id(self):x}>'

    def update_hlen(self) -> None:
        self.header.length = len(self.__bytearray__()) - len(self.header)

    @abc.abstractmethod
    def parse(self, packet: bytearray) -> None:
        if self.header.typeid is PacketType.Invalid:
            self.header.parse(packet)


class VersionedPacket(Packet):
    __typeid__: Union[PacketType, DispatchGuidance] = DispatchGuidance.NoDispatch
    __headercls__ = VersionedHeader

    def __init__(self) -> None:
        super().__init__()
        if isinstance(self.__ver__, int) and isinstance(self.header, VersionedHeader):
            self.header.version = self.__ver__

    def __repr__(self) -> str:
        if not isinstance(self.header, VersionedHeader):
            raise TypeError(f"VersionedPacket should have VersionedHeader, instead it has {type(self.header)}")
        return f"<{self.__class__.__name__} [type {self.header.typeid:02}][v{self.header.version}] at 0x{id(self):x}>"


class Opaque(Packet):
    __typeid__ = None

    @sdproperty
    def payload(self) -> Union[bytes, bytearray]:
        return self._payload

    @payload.register
    def payload_bin(self, val: Union[bytes, bytearray]) -> None:
        self._payload = val

    def __init__(self) -> None:
        super().__init__()
        self.payload = b''

    def __bytearray__(self) -> bytearray:
        _bytes = super().__bytearray__()
        _bytes += self.payload
        return _bytes

    def parse(self, packet: bytearray) -> None:  # pragma: no cover
        super().parse(packet)
        pend = self.header.length
        if hasattr(self.header, 'version'):
            pend -= 1

        self.payload = packet[:pend]
        del packet[:pend]


# key marker classes for convenience
class Key:
    @abc.abstractproperty
    def pkalg(self) -> PubKeyAlgorithm:
        """The public key algorithm of the key"""


class Public(Key):
    pass


class Private(Key):
    @abc.abstractmethod
    def pubkey(self) -> Public:
        """compute and return the fingerprint of the key"""

    @abc.abstractproperty
    def protected(self) -> bool:
        """Whether the secret key material is protected by a password"""

    @abc.abstractproperty
    def unlocked(self) -> bool:
        """Is the secret key material is protected and also unlocked for use?"""


class Primary(Key):
    pass


class Sub(Key):
    pass


class MPI(int):
    def __new__(cls, num):
        mpi = num

        if isinstance(num, (bytes, bytearray)):
            if isinstance(num, bytes):  # pragma: no cover
                num = bytearray(num)

            fl = ((MPIs.bytes_to_int(num[:2]) + 7) // 8)
            del num[:2]

            mpi = MPIs.bytes_to_int(num[:fl])
            del num[:fl]

        return super().__new__(cls, mpi)

    def byte_length(self) -> int:
        return ((self.bit_length() + 7) // 8)

    def to_mpibytes(self) -> bytes:
        return MPIs.int_to_bytes(self.bit_length(), 2) + MPIs.int_to_bytes(self, self.byte_length())

    def __len__(self) -> int:
        return self.byte_length() + 2


class MPIs(Field):
    # this differs from MPI in that it's subclasses hold/parse several MPI fields
    # and, in the case of v4 private keys, also a String2Key specifier/information.
    __mpis__: Tuple[str, ...] = ()

    def __len__(self) -> int:
        return sum(len(i) for i in self)

    def __iter__(self) -> Iterator[MPI]:
        """yield all components of an MPI so it can be iterated over"""
        for i in self.__mpis__:
            yield getattr(self, i)

    def __copy__(self) -> 'MPIs':
        pk = self.__class__()
        for m in self.__mpis__:
            setattr(pk, m, copy.copy(getattr(self, m)))

        return pk
