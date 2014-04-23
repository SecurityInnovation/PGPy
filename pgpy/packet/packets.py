""" packet.py
"""
import collections
from enum import IntEnum

from .fields import Header, Tag, SubPacket
from ..util import bytes_to_int

def PGPPacket(packet):
    # factory time
    header = Header(packet)
    if header.tag.tag == Tag.Tag.Signature:
        return Signature(packet)

class Packet(object):
    def __init__(self, packet):
        self.header = Header(packet)
        self.parse(packet[len(self.header.raw):])

    def parse(self, packet):
        raise NotImplementedError()

class Signature(Packet):
    class Version(IntEnum):
        ##TODO: parse v3 packets
        v4 = 4

    class Type(IntEnum):
        ##TODO: add more items to Type list
        BinaryDocument = 0x00

    class KeyAlgo(IntEnum):
        RSAEncryptOrSign = 0x01
        RSAEncrypt = 0x02
        RSASign = 0x03
        ##TODO: bother with Elgamel?
        DSA = 0x11

    class HashAlgo(IntEnum):
        MD5 = 0x01
        SHA1 = 0x02
        RIPEMD160 = 0x03
        SHA256 = 0x08
        SHA384 = 0x09
        SHA512 = 0x0A
        SHA224 = 0x0B

        def __str__(self):
            return str(self.name)

    def __init__(self, packet):
        self.version = 0
        self.type = -1
        self.key_algorithm = 0
        self.hash_algorithm = 0
        self.hashed_subpackets = {"length": 0, "packets": collections.OrderedDict()}
        self.unhashed_subpackets = {"length": 0, "packets": collections.OrderedDict()}
        self.hash2 = None
        self.signature_ints = collections.OrderedDict()

        super(Signature, self).__init__(packet)

    def parse(self, packet):
        self.raw = packet
        self.version = Signature.Version(bytes_to_int(self.raw[0:1]))
        self.type = Signature.Type(bytes_to_int(self.raw[1:2]))
        self.key_algorithm = Signature.KeyAlgo(bytes_to_int(self.raw[2:3]))
        self.hash_algorithm = Signature.HashAlgo(bytes_to_int(self.raw[3:4]))

        # hashed subpackets
        self.hashed_subpackets["length"] = bytes_to_int(self.raw[4:6])
        pos = 6
        end = pos + self.hashed_subpackets["length"]
        while pos < end:
            sp = SubPacket(self.raw[pos:end])
            self.hashed_subpackets["packets"][str(sp.type)] = sp
            pos += len(sp.raw)

        # unhashed subpackets
        self.unhashed_subpackets["length"] = bytes_to_int(self.raw[pos:pos+2])
        pos += 2
        end = pos + self.unhashed_subpackets["length"]
        while pos < end:
            sp = SubPacket(self.raw[pos:end])
            self.unhashed_subpackets["packets"][str(sp.type)] = sp
            pos += len(sp.raw)

        self.hash2 = self.raw[pos:pos + 2]
        pos += 2

        # algorithm-specific integer(s)
        while pos < len(self.raw):
            k = len(list(self.signature_ints.keys()))
            self.signature_ints[k] = {}

            self.signature_ints[k]["length"] = bytes_to_int(self.raw[pos])
            pos += 1

            self.signature_ints[k]["int"] = bytes_to_int(self.raw[pos:pos + self.signature_ints[k]["length"]])
            pos += self.signature_ints[k]["length"]