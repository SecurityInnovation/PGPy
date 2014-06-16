""" subpackets.py
"""
import calendar
from datetime import datetime

from .fields import PacketField
from .pftypes import CompressionAlgo, HashAlgo, PFIntEnum, SymmetricKeyAlgo
from ..util import bytes_to_int, int_to_bytes


class SubPacket(PacketField):
    class Type(PFIntEnum):
        # 0x00 - Reserved
        # 0x01 - Reserved
        SigCreationTime = 0x02
        SigExpirationTime = 0x03
        ExportableCertification = 0x04
        TrustSignature = 0x05
        RegularExpression = 0x06
        Revocable = 0x07
        # 0x08 - Reserved
        KeyExpirationTime = 0x09
        # 0x0A - Placeholder for backwards compatibility
        PreferredSymmetricAlgorithms = 0x0B
        RevocationKey = 0x0C
        # 0x0D - Reserved
        # 0x0E - Reserved
        # 0x0F - Reserved
        Issuer = 0x10
        # 0x11 - Reserved
        # 0x12 - Reserved
        # 0x13 - Reserved
        NotationData = 0x14
        PreferredHashAlgorithms = 0x15
        PreferredCompressionAlgorithms = 0x16
        KeyServerPreferences = 0x17
        PreferredKeyServer = 0x18
        PrimaryUserID = 0x19
        PolicyURL = 0x1A
        KeyFlags = 0x1B
        SignerUserID = 0x1C
        RevocationReason = 0x1D
        Features = 0x1E
        SignatureTarget = 0x1F
        EmbeddedSignature = 0x20

        @property
        def subclass(self):
            classes = {'SigCreationTime': SigCreationTime,
                       'SigExpirationTime': SigExpirationTime,
                       'ExportableCertification': None,
                       'TrustSignature': None,
                       'RegularExpression': None,
                       'Revocable': Revocable,
                       'KeyExpirationTime': KeyExpirationTime,
                       'PreferredSymmetricAlgorithms': PreferredSymmetricAlgorithm,
                       'RevocationKey': None,
                       'Issuer': Issuer,
                       'NotationData': None,
                       'PreferredHashAlgorithms': PreferredHashAlgorithm,
                       'PreferredCompressionAlgorithms': PreferredCompressionAlgorithm,
                       'KeyServerPreferences': KeyServerPreferences,
                       'PrimaryUserID': PrimaryUserID,
                       'PolicyURL': None,
                       'KeyFlags': KeyFlags,
                       'SignerUserID': None,
                       'RevocationReason': None,
                       'Features': Features,
                       'EmbeddedSignature': EmbeddedSignature}

            if classes[self.name] is not None:
                return classes[self.name]

            raise NotImplementedError(self.name)  # pragma: no cover

        def __str__(self):
            return self.subclass.name

    name = ""

    def __init__(self, packet=None):
        self.length = 0
        self.type = 0
        self.payload = bytes()

        super(SubPacket, self).__init__(packet)

    def parse(self, packet):
        # subpacket lengths can be 1, 2, or 5 octets long
        if bytes_to_int(packet[:1]) + 1 < 192:
            self.length = bytes_to_int(packet[:1]) + 1
            pos = 1

        elif 255 > bytes_to_int(packet[:1]) >= 192:
            # self.length = bytes_to_int(packet[:2]) + 1
            elen = bytes_to_int(packet[:2])
            self.length = ((elen - (192 << 8)) & 0xFF00) + ((elen & 0xFF) + 192)
            pos = 2

        else:
            self.length = bytes_to_int(packet[1:5]) + 5
            pos = 5

        packet = packet[:self.length]
        self.type = SubPacket.Type(bytes_to_int(packet[pos:(pos + 1)]))
        pos += 1

        try:
            self.__class__ = self.type.subclass(packet).__class__
            self.parse(packet)

        except NotImplementedError:
            self.payload = packet[pos:]

    def __bytes__(self):
        _bytes = int_to_bytes(self.length - 1)
        _bytes += self.type.__bytes__()

        try:
            self.type.subclass

        except NotImplementedError:
            _bytes += self.payload

        return _bytes


class SigCreationTime(SubPacket):
    name = "signature creation time"

    def parse(self, packet):
        self.payload = datetime.utcfromtimestamp(bytes_to_int(packet[2:]))

    def __bytes__(self):
        _bytes = super(SigCreationTime, self).__bytes__()
        _bytes += int_to_bytes(calendar.timegm(self.payload.timetuple()), self.length - 2)
        return _bytes


class ExpirationTime(SubPacket):
    def parse(self, packet):
        self.payload = self.payload = bytes_to_int(packet[2:])

    def __bytes__(self):
        _bytes = super(ExpirationTime, self).__bytes__()
        _bytes += int_to_bytes(self.payload, self.length - 2)
        return _bytes


class SigExpirationTime(ExpirationTime):
    pass


class KeyExpirationTime(ExpirationTime):
    pass


class BooleanSubPacket(SubPacket):
    def parse(self, packet):
        self.payload = True if bytes_to_int(packet[2:3]) == 1 else False

    def __bytes__(self):
        _bytes = super(BooleanSubPacket, self).__bytes__()
        _bytes += int_to_bytes(1 if self.payload else 0)
        return _bytes


class Revocable(BooleanSubPacket):
    pass


class PrimaryUserID(BooleanSubPacket):
    pass


class PreferredAlgorithm(SubPacket):
    def __bytes__(self):
        _bytes = super(PreferredAlgorithm, self).__bytes__()
        for b in self.payload:
            _bytes += b.__bytes__()

        return _bytes


class PreferredSymmetricAlgorithm(PreferredAlgorithm):
    def parse(self, packet):
        self.payload = []
        pos = 2
        while pos < len(packet):
            self.payload.append(SymmetricKeyAlgo(bytes_to_int(packet[pos:(pos + 1)])))
            pos += 1


class PreferredHashAlgorithm(PreferredAlgorithm):
    def parse(self, packet):
        self.payload = []
        pos = 2
        while pos < len(packet):
            self.payload.append(HashAlgo(bytes_to_int(packet[pos:(pos + 1)])))
            pos += 1


class PreferredCompressionAlgorithm(PreferredAlgorithm):
    def parse(self, packet):
        self.payload = []
        pos = 2
        while pos < len(packet):
            self.payload.append(CompressionAlgo(bytes_to_int(packet[pos:(pos + 1)])))
            pos += 1


class Issuer(SubPacket):
    name = "issuer key ID"

    def parse(self, packet):
        # python 2.7
        if type(packet) is str:
            self.payload = ''.join('{:02x}'.format(ord(c)) for c in packet[2:]).upper().encode()

        # python 3.x
        else:
            self.payload = ''.join('{:02x}'.format(c) for c in packet[2:]).upper().encode()

    def __bytes__(self):
        _bytes = super(Issuer, self).__bytes__()
        _bytes += int_to_bytes(int(self.payload, 16), self.length - 2)

        return _bytes


class PreferenceFlags(SubPacket):
    class Flags:
        # Override this in subclasses
        pass

    def parse(self, packet):
        self.payload = []
        bits = bytes_to_int(packet[2:])
        for flag in sorted(self.Flags.__members__.values()):
            if bits & flag.value:
                self.payload.append(flag)

    def __bytes__(self):
        _bytes = super(PreferenceFlags, self).__bytes__()
        _bytes += int_to_bytes(sum([f.value for f in self.payload]), self.length - 2)

        return _bytes


class KeyServerPreferences(PreferenceFlags):
    class Flags(PFIntEnum):
        NoModify = 0x80

        def __str__(self):
            flags = {'NoModify': "No-modify"}

            return flags[self.name]


class KeyFlags(PreferenceFlags):
    class Flags(PFIntEnum):
        CertifyKeys = 0x01
        SignData = 0x02
        EncryptComms = 0x04
        EncryptStorage = 0x08
        PrivateSplit = 0x10
        Authentication = 0x20
        PrivateShared = 0x80

        def __str__(self):
            flags = {'CertifyKeys': "This key may be used to certify other keys",
                     'SignData': "This key may be used to sign data",
                     'EncryptComms': "This key may be used to encrypt communications",
                     'EncryptStorage': "This key may be used to encrypt storage",
                     'PrivateSplit': "The private component of this key may have been split by a secret-sharing mechanism",
                     'Authentication': "This key may be used for authentication",
                     'PrivateShared': "The private component of this key may be in thepossession of more than one person"}

            return flags[self.name]


class Features(PreferenceFlags):
    class Flags(PFIntEnum):
        ModificationDetection = 0x01

        def __str__(self):
            if self == Features.Flags.ModificationDetection:
                return "Modification detection (packets 18 and 19)"

class EmbeddedSignature(SubPacket):
    def parse(self, packet):
        raise NotImplementedError()