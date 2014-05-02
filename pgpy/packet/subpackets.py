""" subpackets.py
"""
import calendar
from datetime import datetime

from . import SymmetricKeyAlgo, CompressionAlgo, HashAlgo
from .fields import PacketField
from .types import PFIntEnum
from ..util import bytes_to_int, int_to_bytes

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

        @property
        def subclass(self):
            if self == SubPacket.Type.SigCreationTime:
                return SigCreationTime

            if self == SubPacket.Type.SigExpirationTime:
                return SigExpirationTime

            if self == SubPacket.Type.KeyExpirationTime:
                return KeyExpirationTime

            if self == SubPacket.Type.Revocable:
                return Revocable

            if self == SubPacket.Type.KeyExpirationTime:
                return KeyExpirationTime

            if self == SubPacket.Type.PreferredSymmetricAlgorithms:
                return PreferredSymmetricAlgorithm

            if self == SubPacket.Type.Issuer:
                return Issuer

            if self == SubPacket.Type.PreferredHashAlgorithms:
                return PreferredHashAlgorithm

            if self == SubPacket.Type.PreferredCompressionAlgorithms:
                return PreferredCompressionAlgorithm

            if self == SubPacket.Type.KeyServerPreferences:
                return KeyServerPreferences

            if self == SubPacket.Type.KeyFlags:
                return KeyFlags

            if self == SubPacket.Type.Features:
                return Features

            raise NotImplementedError(self.name)

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
            raise NotImplementedError(self.name)  # pgrama: no cover

    def __init__(self, packet=None):
        self.length = 0
        self.type = 0
        self.payload = bytes()

        super(SubPacket, self).__init__(packet)

    def parse(self, packet):
        self.length = bytes_to_int(packet[:1]) + 1
        packet = packet[:self.length]
        self.type = SubPacket.Type(bytes_to_int(packet[1:2]))

        try:
            self.__class__ = self.type.subclass(packet).__class__
            self.parse(packet)

        except NotImplementedError:
            self.payload = packet[2:]

    def __bytes__(self):
        _bytes = int_to_bytes(self.length - 1)
        _bytes += self.type.__bytes__()

        try:
            self.type.subclass

        except NotImplementedError:
            _bytes += self.payload

        return _bytes


class SigCreationTime(SubPacket):
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


class Revocable(SubPacket):
    def parse(self, packet):
        self.payload = True if bytes_to_int(packet[2:3]) == 1 else False

    def __bytes__(self):
        _bytes = super(Revocable, self).__bytes__()
        _bytes += int_to_bytes(1 if self.payload else 0)
        return _bytes


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
    def parse(self, packet):
        self.payload = []
        bits = bytes_to_int(packet[2:])
        for flag in list(self.Flags.__members__.values()):
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
            if self == KeyServerPreferences.Flags.NoModify:
                return "No-modify"

            raise NotImplementedError(self.name)


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
            if self == KeyFlags.Flags.CertifyKeys:
                return "This key may be used to certify other keys"

            if self == KeyFlags.Flags.SignData:
                return "This key may be used to sign data"

            if self == KeyFlags.Flags.EncryptComms:
                return "This key may be used to encrypt communications"

            if self == KeyFlags.Flags.EncryptStorage:
                return "This key may be used to encrypt storage"

            if self == KeyFlags.Flags.PrivateSplit:
                return "The private component of this key may have been split by a secret-sharing mechanism"

            if self == KeyFlags.Flags.Authentication:
                return "This key may be used for authentication"

            if self == KeyFlags.Flags.PrivateShared:
                return "The private component of this key may be in thepossession of more than one person"

            raise NotImplementedError(self.name)  # pragma: no cover


class Features(PreferenceFlags):
    class Flags(PFIntEnum):
        ModificationDetection = 0x01

        def __str__(self):
            if self == Features.Flags.ModificationDetection:
                return "Modification detection (packets 18 and 19)"