""" packet.py
"""
import calendar
from datetime import datetime

from .fields import Header, SubPackets, PubKeyAlgo, HashAlgo, SymmetricKeyAlgo
from .keyfields import MPIFields, String2Key
from ..util import bytes_to_int, int_to_bytes, PFIntEnum


def PGPPacket(packetblob):
    # factory time
    header = Header(packetblob)

    if header.tag == Header.Tag.Signature:
        return Signature(packetblob)

    if header.tag in [Header.Tag.PubKey, Header.Tag.PubSubKey]:
        return PubKey(packetblob)

    if header.tag in [Header.Tag.PrivKey, Header.Tag.PrivSubKey]:
        return PrivKey(packetblob)

    if header.tag == Header.Tag.UserID:
        return UserID(packetblob)

    return Packet(packetblob)


class Packet(object):
    def __init__(self, packet):
        self.header = Header(packet)
        start = len(self.header.__bytes__())
        end = start + self.header.length
        self.parse(packet[start:end])

    def parse(self, packet):
        raise NotImplementedError()

    def __bytes__(self):
        raise NotImplementedError()

    def pgpdump_out(self):
        raise NotImplementedError()


class Signature(Packet):
    class Version(PFIntEnum):
        Invalid = 0
        ##TODO: parse v3 packets
        v4 = 4

    class Type(PFIntEnum):
        BinaryDocument = 0x00
        CanonicalDocument = 0x01
        Standalone = 0x02
        Generic_UserID_Pubkey = 0x10
        Persona_UserID_Pubkey = 0x11
        Casual_UserID_Pubkey = 0x12
        Positive_UserID_Pubkey = 0x13
        Subkey_Binding = 0x18
        PrimaryKey_Binding = 0x19
        DirectlyOnKey = 0x1F
        KeyRevocation = 0x20
        SubkeyRevocation = 0x28
        CertRevocation = 0x30
        Timestamp = 0x40
        ThirdParty_Confirmation = 0x50

        def __str__(self):
            if self == Signature.Type.BinaryDocument:
                return "Signature of a binary document"

            if self == Signature.Type.CanonicalDocument:
                return "Signature of a canonical text document"

            if self == Signature.Type.Generic_UserID_Pubkey:
                return "Generic certification of a User ID and Public Key packet"

            if self == Signature.Type.Positive_UserID_Pubkey:
                return "Positive certification of a User ID and Public Key packet"

            if self == Signature.Type.Subkey_Binding:
                return "Subkey Binding Signature"

            if self == Signature.Type.CertRevocation:
                return "Certification revocation signature"

            ##TODO: more of these
            raise NotImplementedError(self.name)

    def __init__(self, packet):
        self.name = "Signature Packet"
        self.version = Signature.Version.Invalid
        self.type = -1
        self.key_algorithm = PubKeyAlgo.Invalid
        self.hash_algorithm = 0
        self.hashed_subpackets = SubPackets()
        self.hashed_subpackets.hashed = True
        self.unhashed_subpackets = SubPackets()
        self.hash2 = b''
        self.signature = MPIFields()

        super(Signature, self).__init__(packet)

    def parse(self, packet):
        self.version = Signature.Version(bytes_to_int(packet[:1]))
        self.type = Signature.Type(bytes_to_int(packet[1:2]))
        self.key_algorithm = PubKeyAlgo(bytes_to_int(packet[2:3]))
        self.hash_algorithm = HashAlgo(bytes_to_int(packet[3:4]))

        # subpackets
        self.hashed_subpackets.parse(packet[4:])
        pos = 4 + self.hashed_subpackets.length

        self.unhashed_subpackets.parse(packet[pos:])
        pos += self.unhashed_subpackets.length

        # hash2
        self.hash2 = packet[pos:pos + 2]
        pos += 2

        # algorithm-specific integer(s)
        self.signature.parse(packet[pos:], self.header.tag, self.key_algorithm)

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


class PubKey(Packet):
    class Version(PFIntEnum):
        Invalid = 0
        ##TODO: parse v3 packets
        v4 = 4

    def __init__(self, packet):
        # Tag 6 Public-Key signature packets and Tag 14 Public-Subkey packets share the same format
        self.name = 'Public Key Packet'
        self.is_subkey = False
        self.secret = False

        self.version = PubKey.Version.Invalid
        self.key_creation = 0
        self.key_algorithm = PubKeyAlgo.Invalid
        self.key_material = MPIFields()

        super(PubKey, self).__init__(packet)

    def parse(self, packet):
        if self.header.tag in [Header.Tag.PubSubKey, Header.Tag.PrivSubKey]:
            self.is_subkey = True
            self.name = 'Public Subkey Packet'

        if self.header.tag in [Header.Tag.PrivKey, Header.Tag.PrivSubKey]:
            self.secret = True

        self.version = PubKey.Version(bytes_to_int(packet[:1]))
        self.key_creation = datetime.utcfromtimestamp(bytes_to_int(packet[1:5]))
        self.key_algorithm = PubKeyAlgo(bytes_to_int(packet[5:6]))
        self.key_material.parse(packet[6:], self.header.tag, self.key_algorithm)

    def __bytes__(self):
        _bytes = b''
        _bytes += self.header.__bytes__()
        _bytes += self.version.__bytes__()
        _bytes += int_to_bytes(calendar.timegm(self.key_creation.timetuple()), 4)
        _bytes += self.key_algorithm.__bytes__()
        _bytes += self.key_material.__bytes__()

        return _bytes


class UserID(Packet):
    def __init__(self, packet):
        self.name = 'User ID Packet'
        self.data = b''

        super(UserID, self).__init__(packet)

    def parse(self, packet):
        self.data = packet

    def __bytes__(self):
        _bytes = b''
        _bytes += self.header.__bytes__()
        _bytes += self.data

        return _bytes


class PrivKey(Packet):
    class Version(PFIntEnum):
        Invalid = 0
        ##TODO: parse v3 packets
        v4 = 4

    def __init__(self, packet):
        # Tag 5 Secret-Key packets and Tag 7 Secret-Subkey packets share the same format
        self.is_subkey = False
        self.version = PrivKey.Version.Invalid
        self.key_creation = 0
        self.key_algorithm = PubKeyAlgo.Invalid
        self.key_material = MPIFields()
        self.stokey = String2Key()
        self.seckey_material = MPIFields()
        self.checksum = b''

        super(PrivKey, self).__init__(packet)

    def parse(self, packet):
        if self.header.tag == Header.Tag.PrivSubKey:
            self.is_subkey = True

        self.version = PrivKey.Version(bytes_to_int(packet[:1]))
        self.key_creation = datetime.utcfromtimestamp(bytes_to_int(packet[1:5]))
        self.key_algorithm = PubKeyAlgo(bytes_to_int(packet[5:6]))
        self.key_material.parse(packet[6:], self.header.tag, self.key_algorithm)
        pos = 6 + len(self.key_material.__bytes__())

        self.stokey.parse(packet[pos:])
        pos += len(self.stokey.__bytes__())

        if self.stokey.id == 0:
            self.seckey_material.parse(packet[pos:], self.header.tag, self.key_algorithm, True)
            pos += len(self.seckey_material.__bytes__())

        else:
            mend = -2
            if self.stokey.id == 254:
                mend = len(packet)
            self.seckey_material = packet[pos:mend]

        if self.stokey.id in [0, 255]:
            self.checksum = packet[pos:]

    def __bytes__(self):
        _bytes = b''
        _bytes += self.header.__bytes__()
        _bytes += self.version.__bytes__()
        _bytes += int_to_bytes(calendar.timegm(self.key_creation.timetuple()), 4)
        _bytes += self.key_algorithm.__bytes__()
        _bytes += self.key_material.__bytes__()
        _bytes += self.stokey.__bytes__()
        if self.stokey.id == 0:
            _bytes += self.seckey_material.__bytes__()
        else:
            _bytes += self.seckey_material
        _bytes += self.checksum

        return _bytes
