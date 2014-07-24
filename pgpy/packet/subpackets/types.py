""" subpacket.py
"""

from ..fields.types import PacketField
from ..types import PFIntEnum
from ...util import bytes_to_int, int_to_bytes


class SubPacket(PacketField):
    class Type(PFIntEnum):
        # override this embedded class in subclasses to add type definitions
        # also implement the subclass property

        @property
        def subclass(self):
            raise NotImplementedError()

        def __str__(self):
            return self.subclass.name

    def __init__(self, packet=None):
        self.length = 0
        self.critical = False
        self.type = 0
        self.payload = bytes()

        super(SubPacket, self).__init__(packet)

    def parse(self, packet):
        # subpacket lengths can be 1, 2, or 5 octets long
        if 192 > bytes_to_int(packet[:1]):
            self.length = bytes_to_int(packet[:1])
            pos = 1

        elif 255 > bytes_to_int(packet[:1]) >= 192:
            elen = bytes_to_int(packet[:2])
            self.length = ((elen - (192 << 8)) & 0xFF00) + ((elen & 0xFF) + 192)
            pos = 2

        else:
            self.length = bytes_to_int(packet[1:5])
            pos = 5

        packet = packet[:pos + self.length]

        # before parsing the type_id, check the critical bit
        type_id = bytes_to_int(packet[pos:(pos + 1)])
        pos += 1
        if type_id & 0x80:
            self.critical = True

        # now mask out the critical bit before trying to parse the subpacket type
        type_id &= 0x7F

        try:
            self.type = self.Type(type_id)

        except ValueError:
            self.type = type_id
            self.__class__ = self.Type.opaque()

        else:
            # morph into a subpacket's subclass and call that class' parse
            self.__class__ = self.type.subclass

        finally:
            self.parse(packet[pos:])

    def __bytes__(self):
        _bytes = b''
        if 192 > self.length:
            _bytes += int_to_bytes(self.length)

        elif 192 <= self.length < 8384:
            _bytes += int_to_bytes(((self.length & 0xFF00) + (192 << 8)) + ((self.length & 0xFF) - 192), 2)

        else:
            _bytes += b'\xFF' + int_to_bytes(self.length, 4)

        _bytes += self.type.__bytes__()
        return _bytes
