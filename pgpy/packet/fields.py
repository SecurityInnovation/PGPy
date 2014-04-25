""" fields.py
"""
import collections
import math
import calendar
from datetime import datetime
from enum import IntEnum

from ..util import bytes_to_int, int_to_bytes, PFIntEnum
from .. import PGPError


class PacketField(object):
    def __init__(self, packet=None):
        if packet is not None:
            self.parse(packet)

    def parse(self, packet):
        """
        :param packet: raw packet bytes
        """
        raise NotImplementedError()

    def __bytes__(self):
        raise NotImplementedError()


class Header(PacketField):
    class Format(IntEnum):
        old = 0
        new = 1

    class Tag(IntEnum):
        Invalid = 0
        Signature = 2
        PrivKey = 5
        PubKey = 6

    def __init__(self, packet=None):
        self.always_1 = 0
        self.format = Header.Format.old
        self.tag = Header.Tag.Invalid
        self.length_type = 0
        self.length = 0

        super(Header, self).__init__(packet)

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
        # parse the tag
        tag = bytes_to_int(packet[:1])

        self.always_1 = tag >> 7
        if self.always_1 != 1:
            raise PGPError("Malformed tag!")

        self.format = Header.Format((tag >> 6) & 1)

        # determine the tag and packet length
        # old style packet header
        if self.format == Header.Format.old:
            self.tag = Header.Tag((tag >> 2) & 0xF)
            self.length_type = tag & 0x3

            if self.length_type == 0:
                packet = packet[:2]

            elif self.length_type == 1:
                packet = packet[:3]

            elif self.length_type == 2:
                packet = packet[:6]

            else:
                packet = packet[:1]

        # new style packet header
        else:
            self.tag = Header.Tag(tag & 0x3F)

            if bytes_to_int(packet[1:2]) < 191:
                packet = packet[:2]

            if bytes_to_int(packet[1:2]) > 191:
                packet = packet[:3]

            if bytes_to_int(packet[2:3] > 8383):
                packet = packet[:6]

        # make sure the Tag is valid
        if self.tag == Header.Tag.Invalid:
            raise PGPError("Invalid tag!")

        # if the length is provided, parse it
        if len(packet) > 1:
            self.length = bytes_to_int(packet[1:])

    def __bytes__(self):
        _bytes = self.always_1 << 7
        _bytes += self.format << 6

        if self.format == Header.Format.old:
            _bytes += self.tag << 2

            # compute length_type if it isn't already provided
            if self.length_type == 0:
                while self.length >> (8*(self.length_type+1)) and self.length_type < 3:
                    self.length_type += 1

            _bytes += self.length_type

        else:
            _bytes += self.tag

        _bytes = int_to_bytes(_bytes)

        _bytes += int_to_bytes(self.length)

        return _bytes



class SubPacket(PacketField):
    class Type(PFIntEnum):
        ##TODO: parse more of these
        CreationTime = 0x02
        ExpirationTime = 0x03
        Issuer = 0x10

        def __str__(self):
            return str(self.name)

    def __init__(self, packet=None):
        self.length = 0
        self.type = 0
        self.payload = bytes()

        super(SubPacket, self).__init__(packet)

    def parse(self, packet):
        self.length = bytes_to_int(packet[:1]) + 1
        packet = packet[:self.length]

        self.type = SubPacket.Type(bytes_to_int(packet[1:2]))

        if self.type == SubPacket.Type.CreationTime:
            self.payload = datetime.utcfromtimestamp(bytes_to_int(packet[2:]))

        elif self.type == SubPacket.Type.Issuer:
            # python 2.7
            if type(packet) is str:
                self.payload = ''.join('{:02x}'.format(ord(c)) for c in packet[2:]).upper().encode()
            # python 3.x
            else:
                self.payload = ''.join('{:02x}'.format(c) for c in packet[2:]).upper().encode()

        else:
            self.payload = packet[2:]

    def __bytes__(self):
        _bytes = int_to_bytes(self.length - 1)

        _bytes += self.type.__bytes__()

        if self.type == SubPacket.Type.CreationTime:
            _bytes += int_to_bytes(calendar.timegm(self.payload.timetuple()), self.length - 2)

        elif self.type == SubPacket.Type.Issuer:
            _bytes += int_to_bytes(int(self.payload, 16), self.length - 2)

        else:
            _bytes += self.payload

        return _bytes


class SubPackets(PacketField):
    def __init__(self, packet=None):
        self.length = 0
        self.hashed = False
        self.subpackets = collections.OrderedDict()

        super(SubPackets, self).__init__(packet)

    def parse(self, packet):
        self.length = bytes_to_int(packet[0:2]) + 2
        packet = packet[:(self.length)]

        pos = 2
        while pos < self.length:
            sp = SubPacket(packet[pos:])
            self.subpackets[str(sp.type)] = sp
            pos += sp.length

    def __getattr__(self, name):
        if name in self.subpackets.keys():
            return self.subpackets[name]

        else:
            raise AttributeError()

    def __bytes__(self):
        _bytes = int_to_bytes(self.length - 2, 2)

        for _, subpacket in self.subpackets.items():
            _bytes += subpacket.__bytes__()

        return _bytes


class SignatureField(PacketField):
    def __init__(self, packet=None):
        self.length = []
        self.signatures = []

        super(SignatureField, self).__init__(packet)

    def parse(self, packet):
        pos = 0
        while pos < len(packet):
            i = len(self.length)

            self.length.append(bytes_to_int(packet[pos:(pos + 2)]))
            pos += 2

            mlen = int(math.ceil(self.length[i] / 8.0))
            mend = pos + mlen

            self.signatures.append(packet[pos:mend])

            pos = mend

    def __bytes__(self):
        _bytes = b''

        for i in range(0, len(self.length)):
            _bytes += int_to_bytes(self.length[i], 2)
            _bytes += self.signatures[i]

        return _bytes