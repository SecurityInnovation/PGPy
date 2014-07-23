""" signature.py

Signature SubPackets
"""
import abc
import calendar
from datetime import datetime

from .types import MetaSubPacket
from .types import SubPacket

from ..types import CompressionAlgo
from ..types import HashAlgo
from ..types import PFIntEnum
from ..types import SymmetricKeyAlgo
from ...util import bytes_to_int
from ...util import int_to_bytes


# class SignatureSubPacket(type):
#     """
#     Metaclass that does two things:
#      - Automatically registers appropriate classes that are:
#        - subclasses of SigSubPacket
#        - return a non-reserved integer value from the `id` parameter
#
#      - Acts as a factory, returning the correct class instance when one is being parsed
#     """
#     id_registry = {0x00: "Reserved",
#                    0x01: "Reserved",
#                    0x08: "Reserved",
#                    0x0A: "Reserved",
#                    0x11: "Reserved",
#                    0x12: "Reserved",
#                    0x13: "Reserved"}
#     """
#     id_registry stores all of the subpacket classes as they are registered, for use upon instantiation.
#
#     Signature Subpacket types:
#
#     # 0x00 - Reserved
#     # 0x01 - Reserved
#     0x02 - SigCreationTime
#     0x03 - SigExpirationTime
#     0x04 - ExportableCertification = 0x04
#     0x05 - TrustSignature = 0x05
#     0x06 - RegularExpression = 0x06
#     0x07 - Revocable = 0x07
#     # 0x08 - Reserved
#     0x09 - KeyExpirationTime = 0x09
#     # 0x0A - Placeholder for backwards compatibility
#     0x0B - PreferredSymmetricAlgorithms = 0x0B
#     0x0C - RevocationKey = 0x0C
#     0x0D - Reserved
#     0x0E - Reserved
#     0x0F - Reserved
#     0x10 - Issuer = 0x10
#     # 0x11 - Reserved
#     # 0x12 - Reserved
#     # 0x13 - Reserved
#     0x14 - NotationData = 0x14
#     0x15 - PreferredHashAlgorithms = 0x15
#     0x16 - PreferredCompressionAlgorithms = 0x16
#     0x17 - KeyServerPreferences = 0x17
#     0x18 - PreferredKeyServer = 0x18
#     0x19 - PrimaryUserID = 0x19
#     0x1A - PolicyURL = 0x1A
#     0x1B - KeyFlags = 0x1B
#     0x1C - SignerUserID = 0x1C
#     0x1D - RevocationReason = 0x1D
#     0x1E - Features = 0x1E
#     0x1F - SignatureTarget = 0x1F
#     0x20 - EmbeddedSignature = 0x20
#     """
#
#     def __new__(cls, name, bases, nmspc):
#         new = super(SignatureSubPacket, cls).__new__(cls, name, bases, nmspc)
#
#         # register the subclass in the registry
#         if hasattr(new, 'id') and new.id not in SignatureSubPacket.id_registry:

# class SigSubPacket(SubPacket):
#     @staticmethod
#     def load_subpacket(packet):
#         def _subclasses(cls):
#             subs = cls.__subclasses__()
#             for d in list(subs):
#                 subs.extend(_subclasses(d))
#
#             return subs
#
#         new = SubPacket()
#         new.parse(packet)
#
#         sub = [x for x in _subclasses(SigSubPacket) if x.type == new.type]
#
#         if len(sub) > 0:
#             new = sub[0]()
#             new.parse(packet)
#             return new
#
#         raise ValueError("Parsing failed :(")
class SignatureSubPacket(SubPacket):
    pass

class OpaqueSubPacket(SignatureSubPacket):
    id = None

    def __init__(self):
        super(OpaqueSubPacket, self).__init__()
        self.payload = b''

    def parse(self, packet):
        packet = super(OpaqueSubPacket, self).parse(packet)
        self.payload = packet[:self.length - 1]

        return packet[self.length - 1:]

    def __bytes__(self):
        _bytes = super(OpaqueSubPacket, self).__bytes__()
        _bytes += self.payload
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()

class SigCreationTime(SignatureSubPacket):
    id = 0x02

    @property
    def name(self):
        return "signature creation time"

    def __init__(self):
        super(SigCreationTime, self).__init__()
        self.payload = datetime.utcnow()

    def parse(self, packet):
        packet = super(SigCreationTime, self).parse(packet)
        self.payload = datetime.utcfromtimestamp(bytes_to_int(packet[:(self.length - 1)]))

    def __bytes__(self):
        _bytes = super(SigCreationTime, self).__bytes__()
        _bytes += int_to_bytes(calendar.timegm(self.payload.timetuple()), self.length - 1)
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()


# class ExpirationTime(SignatureSubPacket):
#     def parse(self, packet):
#         self.payload = self.payload = bytes_to_int(packet)
#
#     def __bytes__(self):
#         _bytes = super(ExpirationTime, self).__bytes__()
#         _bytes += int_to_bytes(self.payload, self.length - 1)
#         return _bytes
#
#
# class SigExpirationTime(ExpirationTime):
#     pass
#
#
# class KeyExpirationTime(ExpirationTime):
#     name = "key expiration time"
#
#
# class BooleanSigSubPacket(SignatureSubPacket):
#     def parse(self, packet):
#         self.payload = True if bytes_to_int(packet[:1]) == 1 else False
#
#     def __bytes__(self):
#         _bytes = super(BooleanSigSubPacket, self).__bytes__()
#         _bytes += int_to_bytes(1 if self.payload else 0)
#         return _bytes
#
#
# class Revocable(BooleanSigSubPacket):
#     name = "revocable"
#
#
# class PrimaryUserID(BooleanSigSubPacket):
#     name = "primary User ID"
#
#
# class PolicyURL(SignatureSubPacket):
#     name = "policy URL"
#
#     def parse(self, packet):
#         self.payload = packet
#
#     def __bytes__(self):
#         _bytes = super(PolicyURL, self).__bytes__()
#         _bytes += self.payload
#         return _bytes
#
#
# class PreferredAlgorithm(SigSubPacket):
#     def __bytes__(self):
#         _bytes = super(PreferredAlgorithm, self).__bytes__()
#         for b in self.payload:
#             _bytes += b.__bytes__()
#         return _bytes
#
#
# class PreferredSymmetricAlgorithm(PreferredAlgorithm):
#     name = "preferred symmetric algorithms"
#
#     def parse(self, packet):
#         self.payload = []
#         pos = 0
#         while pos < len(packet):
#             self.payload.append(SymmetricKeyAlgo(bytes_to_int(packet[pos:(pos + 1)])))
#             pos += 1
#
#
# class PreferredHashAlgorithm(PreferredAlgorithm):
#     name = "preferred hash algorithms"
#
#     def parse(self, packet):
#         self.payload = []
#         pos = 0
#         while pos < len(packet):
#             self.payload.append(HashAlgo(bytes_to_int(packet[pos:(pos + 1)])))
#             pos += 1
#
#
# class PreferredCompressionAlgorithm(PreferredAlgorithm):
#     name = "preferred compression algorithms"
#
#     def parse(self, packet):
#         self.payload = []
#         pos = 0
#         while pos < len(packet):
#             self.payload.append(CompressionAlgo(bytes_to_int(packet[pos:(pos + 1)])))
#             pos += 1
#
#
class Issuer(SignatureSubPacket):
    name = "issuer key ID"
    id = 0x10

    def __init__(self):
        super(Issuer, self).__init__()

        self.payload = ""

    def parse(self, packet):
        packet = super(Issuer, self).parse(packet)

        # python 2.7
        if type(packet) is str:
            self.payload = ''.join('{:02x}'.format(ord(c)) for c in packet[:8]).upper().encode()

        # python 3.x
        else:
            self.payload = ''.join('{:02x}'.format(c) for c in packet[:8]).upper().encode()

        return packet[8:]

    def __bytes__(self):
        _bytes = super(Issuer, self).__bytes__()
        _bytes += int_to_bytes(int(self.payload, 16), self.length - 1)
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()


# class PreferenceFlags(PFIntEnum):
    # flags get added in subclasses

    # def parse(self, packet):
    #
    #     self.payload = []
    #     bits = bytes_to_int(packet)
    #     for flag in sorted(self.Flags.__members__.values()):
    #         if bits & flag.value:
    #             self.payload.append(flag)
    #
    # def __bytes__(self):
    #     _bytes = super(PreferenceFlags, self).__bytes__()
    #     _bytes += int_to_bytes(sum([f.value for f in self.payload]), self.length - 1)
    #     return _bytes
#
#
# class KeyServerPreferences(PreferenceFlags):
#     class Flags(PFIntEnum):
#         NoModify = 0x80
#
#         def __str__(self):
#             flags = {'NoModify': "No-modify"}
#
#             return flags[self.name]
#
#     name = "key server preferences"
#
#
# class PreferenceFlags(object):
#     class Flags(PFIntEnum):
#         # flags go here
#         pass
#
#     # def __init__(self):
#     #     for flag in sorted(self.Flags.__members__.values()):
#     #         self.__class__
#
#     def parse(self, packet):
#         self.payload = bytes_to_int(packet[:1])
#         return packet[1:]
#
#     def __bytes__(self):
#         return int_to_bytes(self.payload)

class KeyFlags(SignatureSubPacket):
    class Flags(PFIntEnum):
        CertifyKeys = 0x01
        # CertifyKeys.__str__ = lambda: "This key may be used to certify other keys"
        SignData = 0x02
        # SignData.__str__ = lambda: "This key may be used to sign data"
        EncryptComms = 0x04
        # EncryptComms.__str__ = lambda: "This key may be used to encrypt communications"
        EncryptStorage = 0x08
        # EncryptStorage.__str__ = lambda: "This key may be used to encrypt storage"
        PrivateSplit = 0x10
        # PrivateSplit.__str__ = lambda: "The private component of this key may have been split by a secret-sharing mechanism"
        Authentication = 0x20
        # Authentication.__str__ = "This key may be used for authentication"
        PrivateShared = 0x80
        # PrivateShared.__str__ = "The private component of this key may be in the possession of more than one person"

    name = "key flags"
    id = 0x1B

    def __init__(self):
        super(KeyFlags, self).__init__()
        self.flags = 0x00

    def parse(self, packet):
        packet = super(KeyFlags, self).parse(packet)
        self.flags = bytes_to_int(packet[:1])
        return packet[1:]

    def __bytes__(self):
        _bytes = super(KeyFlags, self).__bytes__()
        _bytes += int_to_bytes(self.flags)
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()

#
#
# class Features(PreferenceFlags):
#     class Flags(PFIntEnum):
#         ModificationDetection = 0x01
#
#         def __str__(self):
#             if self == Features.Flags.ModificationDetection:
#                 return "Modification detection (packets 18 and 19)"
#
#     name = "features"
#
#
# class EmbeddedSignature(SigSubPacket):
#     """
#     5.2.3.26.  Embedded Signature
#
#     (1 signature packet body)
#
#     This subpacket contains a complete Signature packet body as
#     specified in Section 5.2 above.  It is useful when one signature
#     needs to refer to, or be incorporated in, another signature.
#     """
#
#     class FakeHeader(object):
#         tag = None
#
#         def __bytes__(self):
#             return b''
#
#     name = "embedded signature"
#
#     def parse(self, packet):
#         from ..fields.fields import Header
#         from ..packets import Signature
#
#         self.payload = Signature()
#         # this is a dirty hack, and I'm not proud of it
#         self.payload.header = EmbeddedSignature.FakeHeader()
#         self.payload.header.tag = Header.Tag.Signature
#         self.payload.parse(packet)
#
#     def __bytes__(self):
#         _bytes = super(EmbeddedSignature, self).__bytes__()
#         _bytes += self.payload.__bytes__()
#         return _bytes
