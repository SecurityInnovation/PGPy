""" fields.py
"""
import calendar
from datetime import datetime
from enum import IntEnum

from ..util import bytes_to_int, int_to_bytes, PFIntEnum
from .. import PGPError


class PubKeyAlgo(PFIntEnum):
    Invalid = 0x00
    RSAEncryptOrSign = 0x01
    RSAEncrypt = 0x02
    RSASign = 0x03
    ElGamal = 0x10
    DSA = 0x11

    def __str__(self):
        if self == PubKeyAlgo.RSAEncryptOrSign:
            return "RSA Encrypt or Sign"

        if self == PubKeyAlgo.ElGamal:
            return "ElGamal Encrypt-Only"

        if self == PubKeyAlgo.DSA:
            return "DSA Digital Signature Algorithm"

        ##TODO: do the rest of these
        raise NotImplementedError(self.name)


class SymmetricKeyAlgo(PFIntEnum):
    Plaintext = 0x00
    IDEA = 0x01
    TripleDES = 0x02
    CAST5 = 0x03
    Blowfish = 0x04
    AES128 = 0x07
    AES192 = 0x08
    AES256 = 0x09
    Twofish256 = 0x0A

    def __str__(self):
        if self == SymmetricKeyAlgo.TripleDES:
            return "Triple-DES"

        if self == SymmetricKeyAlgo.CAST5:
            return "CAST5"

        if self == SymmetricKeyAlgo.AES128:
            return "AES with 128-bit key"

        if self == SymmetricKeyAlgo.AES192:
            return "AES with 192-bit key"

        if self == SymmetricKeyAlgo.AES256:
            return "AES with 256-bit key"

        raise NotImplementedError(self.name)

    def block_size(self):
        if self == SymmetricKeyAlgo.CAST5:
            return 64

        raise NotImplementedError(self.name)

    def keylen(self):
        if self == SymmetricKeyAlgo.CAST5:
            return 128

        raise NotImplementedError(self.name)


class CompressionAlgo(PFIntEnum):
    Uncompressed = 0x00
    ZIP = 0x01
    ZLIB = 0x02
    BZ2 = 0x03

    def __str__(self):
        if self == CompressionAlgo.Uncompressed:
            return "Uncompressed"

        if self == CompressionAlgo.ZIP:
            return "ZIP <RFC1951>"

        if self == CompressionAlgo.ZLIB:
            return "ZLIB <RFC1950>"

        if self == CompressionAlgo.BZ2:
            return "BZip2"

        raise NotImplementedError(self.name)


class HashAlgo(PFIntEnum):
    Invalid = 0x00
    MD5 = 0x01
    SHA1 = 0x02
    RIPEMD160 = 0x03
    SHA256 = 0x08
    SHA384 = 0x09
    SHA512 = 0x0A
    SHA224 = 0x0B

    def __str__(self):
        return self.name

    def digestlen(self):
        if self == HashAlgo.SHA1:
            return 160

        raise NotImplementedError()


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
        PrivSubKey = 7
        PubKey = 6
        Trust = 12
        UserID = 13
        PubSubKey = 14

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
        SigCreationTime = 0x02
        SigExpirationTime = 0x03
        Revocable = 0x07
        KeyExpirationTime = 0x09
        PreferredSymmetricAlgorithms = 0x0B
        Issuer = 0x10
        PreferredHashAlgorithms = 0x15
        PreferredCompressionAlgorithms = 0x16
        KeyServerPreferences = 0x17
        PolicyURL = 0x1A
        KeyFlags = 0x1B
        Features = 0x1E

        def __str__(self):
            if self == SubPacket.Type.SigCreationTime:
                return "signature creation time"

            if self == SubPacket.Type.Issuer:
                return "issuer key ID"

            if self == SubPacket.Type.Revocable:
                return "revocable"

            if self == SubPacket.Type.KeyExpirationTime:
                return "key expiration time"

            if self == SubPacket.Type.PreferredSymmetricAlgorithms:
                return "preferred symmetric algorithms"

            if self == SubPacket.Type.PreferredHashAlgorithms:
                return "preferred hash algorithms"

            if self == SubPacket.Type.PreferredCompressionAlgorithms:
                return "preferred compression algorithms"

            if self == SubPacket.Type.PolicyURL:
                return "policy URL"

            if self == SubPacket.Type.KeyFlags:
                return "key flags"

            if self == SubPacket.Type.Features:
                return "features"

            if self == SubPacket.Type.KeyServerPreferences:
                return "key server preferences"

            ##TODO: the rest of these
            raise NotImplementedError(self.name)

    class KeyFlags(PFIntEnum):
        CertifyKeys = 0x01
        SignData = 0x02
        EncryptComms = 0x04
        EncryptStorage = 0x08
        PrivateSplit = 0x10
        Authentication = 0x20
        PrivateShared = 0x80

        def __str__(self):
            if self == SubPacket.KeyFlags.CertifyKeys:
                return "This key may be used to certify other keys"

            if self == SubPacket.KeyFlags.SignData:
                return "This key may be used to sign data"

            if self == SubPacket.KeyFlags.EncryptComms:
                return "This key may be used to encrypt communications"

            if self == SubPacket.KeyFlags.EncryptStorage:
                return "This key may be used to encrypt storage"

            if self == SubPacket.KeyFlags.PrivateSplit:
                return "The private component of this key may have been split by a secret-sharing mechanism"

            if self == SubPacket.KeyFlags.Authentication:
                return "This key may be used for authentication"

            if self == SubPacket.KeyFlags.PrivateShared:
                return "The private component of this key may be in thepossession of more than one person"

            raise NotImplementedError(self.name)

    class Features(PFIntEnum):
        ModificationDetection = 0x01

        def __str__(self):
            if self == SubPacket.Features.ModificationDetection:
                return "Modification detection (packets 18 and 19)"

    class KeyServerPreferences(PFIntEnum):
        NoModify = 0x80

        def __str__(self):
            if self == SubPacket.KeyServerPreferences.NoModify:
                return "No-modify"

    def __init__(self, packet=None):
        self.length = 0
        self.type = 0
        self.payload = bytes()

        super(SubPacket, self).__init__(packet)

    def parse(self, packet):
        self.length = bytes_to_int(packet[:1]) + 1
        packet = packet[:self.length]

        self.type = SubPacket.Type(bytes_to_int(packet[1:2]))

        if self.type == SubPacket.Type.SigCreationTime:
            self.payload = datetime.utcfromtimestamp(bytes_to_int(packet[2:]))

        elif self.type in [SubPacket.Type.SigExpirationTime, SubPacket.Type.KeyExpirationTime]:
            self.payload = bytes_to_int(packet[2:])

        elif self.type == SubPacket.Type.Revocable:
            self.payload = True if bytes_to_int(packet[2:3]) == 1 else False

        elif self.type == SubPacket.Type.PreferredSymmetricAlgorithms:
            self.payload = []
            pos = 2
            while pos < len(packet):
                self.payload.append(SymmetricKeyAlgo(bytes_to_int(packet[pos:(pos + 1)])))
                pos += 1

        elif self.type == SubPacket.Type.Issuer:
            # python 2.7
            if type(packet) is str:
                self.payload = ''.join('{:02x}'.format(ord(c)) for c in packet[2:]).upper().encode()

            # python 3.x
            else:
                self.payload = ''.join('{:02x}'.format(c) for c in packet[2:]).upper().encode()

        elif self.type == SubPacket.Type.PreferredHashAlgorithms:
            self.payload = []
            pos = 2
            while pos < len(packet):
                self.payload.append(HashAlgo(bytes_to_int(packet[pos:(pos + 1)])))
                pos += 1

        elif self.type == SubPacket.Type.PreferredCompressionAlgorithms:
            self.payload = []
            pos = 2
            while pos < len(packet):
                self.payload.append(CompressionAlgo(bytes_to_int(packet[pos:(pos + 1)])))
                pos += 1

        elif self.type == SubPacket.Type.KeyServerPreferences:
            self.payload = []
            bits = bytes_to_int(packet[2:])
            for flag in list(self.KeyServerPreferences.__members__.values()):
                if bits & flag.value:
                    self.payload.append(flag)

        elif self.type == SubPacket.Type.KeyFlags:
            self.payload = []
            bits = bytes_to_int(packet[2:])
            fl = 1
            while fl < max([ f.value for f in self.KeyFlags.__members__.values() ]):
                if bits & fl:
                    self.payload.append(self.KeyFlags(fl))
                fl <<= 1

        elif self.type == SubPacket.Type.Features:
            self.payload = []
            bits = bytes_to_int(packet[2:])
            for flag in list(self.Features.__members__.values()):
                if bits & flag.value:
                    self.payload.append(flag)

        else:
            self.payload = packet[2:]

    def __bytes__(self):
        _bytes = int_to_bytes(self.length - 1)

        _bytes += self.type.__bytes__()

        if self.type == SubPacket.Type.SigCreationTime:
            _bytes += int_to_bytes(calendar.timegm(self.payload.timetuple()), self.length - 2)

        elif self.type in [SubPacket.Type.SigExpirationTime, SubPacket.Type.KeyExpirationTime]:
            _bytes += int_to_bytes(self.payload, self.length - 2)

        elif self.type == SubPacket.Type.Revocable:
            _bytes += int_to_bytes(1 if self.payload else 0)

        elif self.type in [SubPacket.Type.PreferredSymmetricAlgorithms,
                           SubPacket.Type.PreferredHashAlgorithms,
                           SubPacket.Type.PreferredCompressionAlgorithms]:
            for b in self.payload:
                _bytes += b.__bytes__()

        elif self.type == SubPacket.Type.Issuer:
            _bytes += int_to_bytes(int(self.payload, 16), self.length - 2)

        elif self.type in [SubPacket.Type.KeyServerPreferences, SubPacket.Type.KeyFlags, SubPacket.Type.Features]:
            _bytes += int_to_bytes(sum([f.value for f in self.payload]), self.length - 2)

        else:
            _bytes += self.payload

        return _bytes


class SubPackets(PacketField):
    def __init__(self, packet=None):
        self.length = 0
        self.hashed = False
        self.subpackets = []

        super(SubPackets, self).__init__(packet)

    def parse(self, packet):
        self.length = bytes_to_int(packet[0:2]) + 2
        packet = packet[:self.length]

        pos = 2
        while pos < self.length:
            sp = SubPacket(packet[pos:])
            self.subpackets.append(sp)
            pos += sp.length

    def __getattr__(self, name):
        if name in [ n.type.name for n in self.subpackets ]:
            i = [ n.type.name for n in self.subpackets ].index(name)
            return self.subpackets[i]

        else:
            raise AttributeError()

    def __bytes__(self):
        _bytes = int_to_bytes(self.length - 2, 2)

        for subpacket in self.subpackets:
            _bytes += subpacket.__bytes__()

        return _bytes