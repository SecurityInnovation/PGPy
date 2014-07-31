""" fields.py
"""
from enum import IntEnum

from .types import PacketField

from ..subpackets.signature import SigSubPacket
from ..subpackets.userattribute import UASubPacket

from ...errors import PGPError
from ...util import bytes_to_int
from ...util import int_to_bytes


class Header(PacketField):
    __slots__ = ['always_1', 'format', 'tag', 'length_type', 'length']

    class Format(IntEnum):
        old = 0
        new = 1

    class Tag(IntEnum):
        ##TODO: implement the rest of these
        Invalid = 0
        Signature = 2
        PrivKey = 5
        PrivSubKey = 7
        PubKey = 6
        Trust = 12
        UserID = 13
        PubSubKey = 14
        UserAttribute = 17

        @property
        def is_signature(self):
            return self == Header.Tag.Signature

        @property
        def is_key(self):
            return self in [Header.Tag.PubKey, Header.Tag.PubSubKey, Header.Tag.PrivKey, Header.Tag.PrivSubKey]

        @property
        def is_privkey(self):
            return self in [Header.Tag.PrivKey, Header.Tag.PrivSubKey]

        @property
        def is_subkey(self):
            return self in [Header.Tag.PubSubKey, Header.Tag.PrivSubKey]

    def __init__(self, packet=None):
        self.always_1 = 1
        self.format = Header.Format.new
        self.tag = Header.Tag.Invalid
        self.length_type = 0
        ##TODO: length should also be computable from the rest of the packet
        #       this means we'll probably need to store a reference to the Packet object
        #       to which this Header instance belongs
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
            raise PGPError("Malformed tag!")  # pragma: no cover

        self.format = Header.Format((tag >> 6) & 1)

        # determine the tag and packet length
        # old style packet header
        if self.format == Header.Format.old:
            self.tag = Header.Tag((tag >> 2) & 0xF)
            self.length_type = tag & 0x3

            lt = {0: lambda: bytes_to_int(packet[1:2]),
                  1: lambda: bytes_to_int(packet[1:3]),
                  2: lambda: bytes_to_int(packet[1:6]),
                  3: lambda: 0}[self.length_type]
            self.length = lt()

        # new style packet header
        else:
            self.tag = Header.Tag(tag & 0x3F)
            fo = bytes_to_int(packet[1:2])

            # 1 octet length
            if fo < 191:
                self.length = bytes_to_int(packet[1:2])

            # 2 octet length
            elif 224 > fo > 191:
                # ((num - (192 << 8)) & 0xFF00) + ((num & 0xFF) + 192)
                elen = bytes_to_int(packet[1:3])
                self.length = ((elen - (192 << 8)) & 0xFF00) + ((elen & 0xFF) + 192)

            # 5 octet length
            elif fo == 255:
                self.length = bytes_to_int(packet[2:6])

            else:
                raise PGPError("Malformed length!")

        # make sure the Tag is valid
        if self.tag == Header.Tag.Invalid:
            raise PGPError("Invalid tag!")  # pragma: no cover

    def __bytes__(self):
        _bytes = b''

        # first byte is bitfields
        fbyte = self.always_1 << 7
        fbyte += self.format << 6

        if self.format == Header.Format.old:
            fbyte += self.tag << 2

            # compute length_type if it isn't already provided
            if self.length_type == 0:
                while self.length >> (8 * (self.length_type + 1)) and self.length_type < 3:
                    self.length_type += 1

            fbyte += self.length_type

        else:
            fbyte += self.tag & 0x3F

        _bytes += int_to_bytes(fbyte)

        if self.format == Header.Format.old:
            if self.length_type != 3:
                _bytes += int_to_bytes(self.length, 1 if self.length_type == 0 else 2 if self.length_type == 1 else 4)

        else:
            if 192 > self.length:
                _bytes += int_to_bytes(self.length)

            elif 8384 > self.length:
                _bytes += int_to_bytes(((self.length & 0xFF00) + (192 << 8)) + ((self.length & 0xFF) - 192))

            else:
                _bytes += b'\xFF' + int_to_bytes(self.length, 4)

        return _bytes


class SignatureSubPackets(PacketField):
    SPType = SigSubPacket

    # property method to get the Issuer subpacket
    # realistically, there will only ever be one of these for a given packet
    @property
    def issuer(self):
        nl = [ n.type.name for n in self.subpackets ]
        return self.subpackets[nl.index("Issuer")]

    def __init__(self, packet=None):
        self.length = 0
        self.hashed = False
        self.subpackets = []
        super(SignatureSubPackets, self).__init__(packet)

    def parse(self, packet):
        self.length = bytes_to_int(packet[0:2]) + 2
        packet = packet[:self.length]

        pos = 2
        while pos < self.length:
            sp = SigSubPacket(packet[pos:])
            self.subpackets.append(sp)
            pos += sp.length
            if 192 > sp.length:
                pos += 1

            elif 8384 > sp.length >= 192:
                pos += 2

            else:
                pos += 5

    def __bytes__(self):
        _bytes = int_to_bytes(self.length - 2, 2)

        for subpacket in self.subpackets:
            _bytes += subpacket.__bytes__()

        return _bytes


class UserAttributeSubPackets(PacketField):
    def __init__(self, packet=None):
        self.subpackets = []
        super(UserAttributeSubPackets, self).__init__(packet)

    def parse(self, packet):
        pos = 0
        while pos < len(packet):
            sp = UASubPacket(packet[pos:])
            self.subpackets.append(sp)

            # this guards against a malformed packet, which apparently can happen
            # because I saw a UA SubPacket today that began b'\xff\x00\x00\x0bX'
            # which is a 5 byte length but only comes out to 2904
            # this will actually be fixed totally differently in 0.3.0
            # because it returns unparsed bytes from *.parse()
            if 192 > bytes_to_int(packet[:1]):
                pos += 1

            elif 255 > bytes_to_int(packet[:1]) >= 192:
                pos += 2

            else:
                pos += 5

            pos += sp.length

    def __bytes__(self):
        _bytes = b''
        for sp in self.subpackets:
            _bytes += sp.__bytes__()

        return _bytes
