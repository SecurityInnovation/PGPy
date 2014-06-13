""" packet.py
"""
import calendar
from datetime import datetime
from enum import Enum

from .fields import Header, SubPackets
from .keyfields import MPIFields, String2Key
from .pftypes import HashAlgo, PFIntEnum, PubKeyAlgo
from ..util import bytes_to_int, int_to_bytes


class PGPPacketClass(Enum):
        # tag support list
        # [x] 0  - Reserved (Illegal Value)
        # [ ] 1  - Public-Key Encrypted Session Key Packet
        # [x] 2  - Signature Packet
        Signature = Header.Tag.Signature
        # [ ] 3  - Symmetric-Key Encrypted Session Key Packet
        # [ ] 4  - One-Pass Signature Packet
        # [x] 5  - Secret-Key Packet
        PrivKey = Header.Tag.PrivKey
        # [x] 6  - Public-Key Packet
        PubKey = Header.Tag.PubKey
        # [x] 7  - Secret-Subkey Packet
        PrivSubKey = Header.Tag.PrivSubKey
        # [ ] 8  - Compressed Data Packet
        # [ ] 9  - Symmetrically Encrypted Data Packet
        # [ ] 10 - Marker Packet
        # [ ] 11 - Literal Data Packet
        # [x] 12 - Trust Packet
        Trust = Header.Tag.Trust
        # [x] 13 - User ID Packet
        UserID = Header.Tag.UserID
        # [x] 14 - Public-Subkey Packet
        PubSubKey = Header.Tag.PubSubKey
        # [x] 17 - User Attribute Packet
        UserAttribute = Header.Tag.UserAttribute
        # [ ] 18 - Sym. Encrypted and Integrity Protected Data Packet
        # [ ] 19 - Modification Detection Code Packet

        @property
        def subclass(self):
            if self == PGPPacketClass.Signature:
                return Signature

            if self in [PGPPacketClass.PubKey, PGPPacketClass.PubSubKey]:
                return PubKey

            if self in [PGPPacketClass.PrivKey, PGPPacketClass.PrivSubKey]:
                return PrivKey

            if self == PGPPacketClass.Trust:
                return Trust

            if self == PGPPacketClass.UserID:
                return UserID

            if self == PGPPacketClass.UserAttribute:
                return UserAttribute

            raise NotImplementedError(self)  # pragma: no cover


class Packet(object):
    name = ""

    def __init__(self, packet=None, ptype=None):
        # __init__ on Packet is now a "factory" of sorts
        #   - if `packet` is None, this is to be a shiny new packet created by PGPy
        #     of type `type`
        #   - if `packet` is not None, this is an existing packet to be parsed
        #     `type` is ignored
        #
        # packet will be None if we're creating a new packet from scratch
        self.header = Header()

        if packet is None and ptype is not None:
            self.header.tag = ptype
            self.__class__ = PGPPacketClass(ptype).subclass
            self.__class__.__init__(self)

        # we're parsing an existing packet
        if packet is not None:
            # parse header, then change into our subclass
            self.header.parse(packet)
            self.__class__ = PGPPacketClass(self.header.tag).subclass
            self.__class__.__init__(self)

            # get the current packet length from the header, then parse it
            start = len(self.header.__bytes__())
            end = start + self.header.length
            self.parse(packet[start:end])

    def parse(self, packet):
        raise NotImplementedError(self.header.tag.name)  # pragma: no cover

    def __bytes__(self):
        raise NotImplementedError(self.header.tag.name)  # pragma: no cover

    def pgpdump_out(self):
        raise NotImplementedError(self.header.tag.name)  # pragma: no cover


class Signature(Packet):
    class Version(PFIntEnum):
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
            raise NotImplementedError(self.name)  # pragma: no cover

    name = "Signature Packet"

    def __init__(self):
        self.version = Signature.Version.v4  # default for new Signature packets
        self.type = Signature.Type.BinaryDocument  # default for new Signature packets
        self.key_algorithm = PubKeyAlgo.RSAEncryptOrSign  # default for new Signature packets
        self.hash_algorithm = 0
        self.hashed_subpackets = SubPackets()
        self.hashed_subpackets.hashed = True
        self.unhashed_subpackets = SubPackets()
        self.hash2 = b''
        self.signature = MPIFields()

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
        _bytes += self.signature.sigbytes()

        return _bytes


class PubKey(Packet):
    class Version(PFIntEnum):
        ##TODO: parse v3 packets
        v4 = 4

    name = "Public Key Packet"

    def __init__(self):
        # Tag 6 Public-Key signature packets and Tag 14 Public-Subkey packets share the same format
        self.is_subkey = False
        self.secret = False
        self.fp = None

        self.version = PubKey.Version.v4  # default for new PubKey packets
        self.key_creation = datetime.utcnow()  # default for new PubKey packets
        self.key_algorithm = PubKeyAlgo.RSAEncryptOrSign  # default for new PubKey packets
        self.key_material = MPIFields()

    def parse(self, packet):
        if self.header.tag.is_subkey:
            self.is_subkey = True
            self.name = 'Public Subkey Packet'

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
        _bytes += self.key_material.pubbytes()

        return _bytes


class UserID(Packet):
    name = "User ID Packet"

    def __init__(self):
        self.data = b''

    def parse(self, packet):
        self.data = packet

    def __bytes__(self):
        _bytes = b''
        _bytes += self.header.__bytes__()
        _bytes += self.data

        return _bytes


class PrivKey(Packet):
    class Version(PFIntEnum):
        ##TODO: parse v3 packets
        v4 = 4

    name = "Secret Key Packet"

    def __init__(self):
        # Tag 5 Secret-Key packets and Tag 7 Secret-Subkey packets share the same format
        self.is_subkey = False
        self.secret = True
        self.fp = None

        self.version = PrivKey.Version.v4  # default for new PrivKey packets
        self.key_creation = datetime.utcnow()  # default for new PrivKey packets
        self.key_algorithm = PubKeyAlgo.RSAEncryptOrSign  # default for new PrivKey packets
        self.key_material = MPIFields()
        self.stokey = String2Key()
        self.enc_seckey_material = b''
        self.checksum = b''

    def parse(self, packet):
        if self.header.tag.is_subkey:
            self.is_subkey = True
            self.name = 'Secret Subkey Packet'

        self.version = PrivKey.Version(bytes_to_int(packet[:1]))
        self.key_creation = datetime.utcfromtimestamp(bytes_to_int(packet[1:5]))
        self.key_algorithm = PubKeyAlgo(bytes_to_int(packet[5:6]))
        self.key_material.parse(packet[6:], self.header.tag, self.key_algorithm)
        pos = 6 + len(self.key_material.pubbytes())

        self.stokey.parse(packet[pos:])
        pos += len(self.stokey.__bytes__())

        # secret key material is not encrypted
        if self.stokey.id == 0:
            self.key_material.parse(packet[pos:], self.header.tag, self.key_algorithm, sec=True)
            pos += len(self.key_material.privbytes())

        # secret key material is encrypted
        else:
            mend = -2
            if self.stokey.id == 254:
                mend = len(packet)
            self.enc_seckey_material = packet[pos:mend]

        if self.stokey.id in [0, 255]:
            self.checksum = packet[pos:]

    def __bytes__(self):
        _bytes = b''
        _bytes += self.header.__bytes__()
        _bytes += self.version.__bytes__()
        _bytes += int_to_bytes(calendar.timegm(self.key_creation.timetuple()), 4)
        _bytes += self.key_algorithm.__bytes__()
        _bytes += self.key_material.pubbytes()
        _bytes += self.stokey.__bytes__()
        if self.stokey.id == 0:
            _bytes += self.key_material.privbytes()
        else:
            _bytes += self.enc_seckey_material
        _bytes += self.checksum

        return _bytes


class Trust(Packet):
    name = "Trust Packet"

    class TrustLevel(PFIntEnum):
        # trust levels
        Unknown = 0
        Expired = 1
        Undefined = 2
        Never = 3
        Marginal = 4
        Fully = 5
        Ultimate = 6

    class TrustFlags(PFIntEnum):
        Revoked = 32
        SubRevoked = 64
        Disabled = 128
        PendingCheck = 256

    @property
    def trust(self):
        return int_to_bytes(self.trustlevel + sum(self.trustflags), 2)

    def __init__(self):
        self.trustlevel = Trust.TrustLevel.Unknown
        self.trustflags = []

    def parse(self, packet):
        # Trust packets contain data that record the user's
        # specifications of which key holders are trustworthy introducers,
        # along with other information that implementing software uses for
        # trust information.  The format of Trust packets is defined by a given
        # implementation.
        # self.trust = packet

        # GPG Trust packet format - see https://github.com/Commod0re/PGPy/issues/14
        self.trustlevel = Trust.TrustLevel(bytes_to_int(packet) % 0xF)
        for tf in sorted(Trust.TrustFlags.__members__.values()):
            if bytes_to_int(packet) & tf.value:
                self.trustflags.append(tf.value)

    def __bytes__(self):
        _bytes = b''
        _bytes += self.header.__bytes__()
        _bytes += self.trust

        return _bytes


class UserAttribute(Packet):
    name = "User Attribute Packet"

    def __init__(self):
        self.contents = ""

    def parse(self, packet):
        ##TODO: these are a separate set of subpackets from the usual subpackets
        ##      defined as User Attribute Subpackets. There is only one currently defined in the standard
        ##      but we should treat it the same way for later extensibility
        ##      for now, let's just store it, though
        self.contents = packet

    def __bytes__(self):
        _bytes = b''
        _bytes += self.header.__bytes__()
        _bytes += self.contents

        return _bytes