""" packet.py
"""
import collections

from .fields import Header, SubPackets, SignatureField
from ..util import bytes_to_int, PFIntEnum

def PGPPacket(packet):
    # factory time
    header = Header(packet)

    if header.tag == Header.Tag.Signature:
        return Signature(packet)


class Packet(object):
    def __init__(self, packet):
        self.header = Header(packet)
        self.parse(packet[len(self.header.raw):])

    def parse(self, packet):
        raise NotImplementedError()

    def __bytes__(self):
        raise NotImplementedError()


class Signature(Packet):
    class Version(PFIntEnum):
        Invalid = 0
        ##TODO: parse v3 packets
        v4 = 4

    class Type(PFIntEnum):
        ##TODO: add more items to Type list
        BinaryDocument = 0x00


    class KeyAlgo(PFIntEnum):
        RSAEncryptOrSign = 0x01
        RSAEncrypt = 0x02
        RSASign = 0x03
        ##TODO: bother with Elgamel?
        DSA = 0x11

    class HashAlgo(PFIntEnum):
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
        self.version = Signature.Version.Invalid
        self.type = -1
        self.key_algorithm = 0
        self.hash_algorithm = 0
        self.hashed_subpackets = SubPackets()
        self.hashed_subpackets.hashed = True
        self.unhashed_subpackets = SubPackets()
        self.hash2 = None
        self.signature = SignatureField()

        super(Signature, self).__init__(packet)

    def parse(self, packet):
        self.raw = packet
        self.version = Signature.Version(bytes_to_int(self.raw[:1]))
        self.type = Signature.Type(bytes_to_int(self.raw[1:2]))
        self.key_algorithm = Signature.KeyAlgo(bytes_to_int(self.raw[2:3]))
        self.hash_algorithm = Signature.HashAlgo(bytes_to_int(self.raw[3:4]))

        # subpackets
        self.hashed_subpackets.parse(self.raw[4:])
        pos = 4 + self.hashed_subpackets.length

        self.unhashed_subpackets.parse(self.raw[pos:])
        pos += self.unhashed_subpackets.length

        # hash2
        self.hash2 = self.raw[pos:pos + 2]
        pos += 2

        # algorithm-specific integer(s)
        self.signature.parse(self.raw[pos:])

    def __bytes__(self):
        _bytes = b''
        _bytes += self.header.__bytes__()
        _bytes += self.version.__bytes__()
        _bytes += self.type.__bytes__()
        _bytes += self.key_algorithm.__bytes__()
        _bytes += self.hash_algorithm.__bytes__()
        _bytes += self.hashed_subpackets.__bytes__()
        _bytes += self.unhashed_subpackets.__bytes__()
        _bytes += self.hash2
        _bytes += self.signature.__bytes__()

        return _bytes