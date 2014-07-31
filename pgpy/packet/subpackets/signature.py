""" signature.py

Signature SubPackets
"""
import calendar
from datetime import datetime

from .types import Signature

from ...constants import CompressionAlgorithm
from ...constants import Features as _Features
from ...constants import HashAlgorithm
from ...constants import KeyFlags as _KeyFlags
from ...constants import KeyServerPreferences as _KeyServerPreferences
from ...constants import NotationDataFlags
from ...constants import PubKeyAlgorithm
from ...constants import RevocationKeyClass
from ...constants import RevocationReason
from ...constants import SymmetricKeyAlgorithm

from ...decorators import TypedProperty

from ...types import Fingerprint


class URI(Signature):
    __slots__ = ['_uri']

    @TypedProperty
    def uri(self):
        return self._uri
    @uri.str
    def uri(self, val):
        self._uri = val
    @uri.bytearray
    @uri.bytes
    def uri(self, val):
        self.uri = val.decode()

    def __init__(self):
        super(URI, self).__init__()
        self.uri = ""

    def __bytes__(self):
        _bytes = super(URI, self).__bytes__()
        _bytes += self.uri.encode()
        return _bytes

    def parse(self, packet):
        super(URI, self).parse(packet)
        self.uri = packet[:(self.header.length - 1)]
        del packet[:(self.header.length - 1)]


class FlagList(Signature):
    __slots__ = ['_flags']
    __flags__ = None

    @TypedProperty
    def flags(self):
        return self._flags
    @flags.list
    def flags(self, val):
        self._flags = val
    @flags.CompressionAlgorithm
    @flags.HashAlgorithm
    @flags.PubKeyAlgorithm
    @flags.SymmetricKeyAlgorithm
    def flags(self, val):
        self.flags.append(val)
    @flags.int
    def flags(self, val):
        if self.__flags__ is None:
            raise AttributeError("Error: __flags__ not set!")

        self.flags.append(self.__flags__(val))
    @flags.bytearray
    @flags.bytes
    def flags(self, val):
        self.flags = self.bytes_to_int(val)

    def __init__(self):
        super(FlagList, self).__init__()
        self.flags = []

    def __bytes__(self):
        _bytes = super(FlagList, self).__bytes__()
        _bytes += b''.join([self.int_to_bytes(b) for b in self.flags])
        return _bytes

    def parse(self, packet):
        super(FlagList, self).parse(packet)
        for i in range(0, self.header.length - 1):
            self.flags = packet[:1]
            del packet[:1]


class ByteFlag(Signature):
    __slots__ = ['_flags']
    __flags__ = None

    @TypedProperty
    def flags(self):
        return self._flags
    @flags.list
    def flags(self, val):
        self._flags = val
    @flags.KeyFlags
    def flags(self, val):
        self.flags.append(val)
    @flags.int
    def flags(self, val):
        if self.__flags__ is None:
            raise AttributeError("Error: __flags__ not set!")
        self.flags += self.__flags__ & val
    @flags.bytearray
    @flags.bytes
    def flags(self, val):
        self.flags = self.bytes_to_int(val)

    def __init__(self):
        super(ByteFlag, self).__init__()
        self.flags = []

    def __bytes__(self):
        _bytes = super(ByteFlag, self).__bytes__()
        _bytes += self.int_to_bytes(sum(self.flags))
        return _bytes

    def parse(self, packet):
        super(ByteFlag, self).parse(packet)
        for i in range(0, self.header.length - 1):
            self.flags = packet[:1]
            del packet[:1]


class CreationTime(Signature):
    __slots__ = ['_created']
    __typeid__ = 0x02

    @TypedProperty
    def created(self):
        return self._created
    @created.datetime
    def created(self, val):
        self._created = val
    @created.int
    def created(self, val):
        self.created = datetime.utcfromtimestamp(val)
    @created.bytearray
    @created.bytes
    def created(self, val):
        self.created = self.bytes_to_int(val)

    def __init__(self):
        super(CreationTime, self).__init__()
        self.created = datetime.utcnow()

    def __bytes__(self):
        _bytes = super(CreationTime, self).__bytes__()
        _bytes += self.int_to_bytes(calendar.timegm(self.created.timetuple()), self.header.length - 1)
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()

    def parse(self, packet):
        super(CreationTime, self).parse(packet)
        self.created = packet[:4]
        del packet[:4]


class SignatureExpirationTime(Signature):
    __slots__ = ['_expires']
    __typeid__ = 0x03

    @TypedProperty
    def expires(self):
        return self._expires
    @expires.int
    def expires(self, val):
        self._expires = val
    @expires.bytearray
    @expires.bytes
    def expires(self, val):
        self.expires = self.bytes_to_int(val)

    def __init__(self):
        super(SignatureExpirationTime, self).__init__()
        self.expires = 0

    def __bytes__(self):
        _bytes = super(SignatureExpirationTime, self).__bytes__()
        _bytes += self.int_to_bytes(self.expires, 4)
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()

    def parse(self, packet):
        super(SignatureExpirationTime, self).parse(packet)
        self.expires = packet[:4]
        del packet[:4]


class TrustSignature(Signature):
    __slots__ = ['_level', '_amount']
    __typeid__ = 0x05

    @TypedProperty
    def level(self):
        return self._level
    @level.int
    def level(self, val):
        self._level = val
    @level.bytearray
    @level.bytes
    def level(self, val):
        self.level = self.bytes_to_int(val)

    @TypedProperty
    def amount(self):
        return self._amount
    @amount.int
    def amount(self, val):
        # clamp 'val' to the range 0-255
        self._amount = max(0, min(val, 255))
    @amount.bytearray
    @amount.bytes
    def amount(self, val):
        self.amount = self.bytes_to_int(val)

    def __init__(self):
        super(TrustSignature, self).__init__()
        self.level = 0
        self.amount = 0

    def __bytes__(self):
        _bytes = super(TrustSignature, self).__bytes__()
        _bytes += self.int_to_bytes(self.level)
        _bytes += self.int_to_bytes(self.amount)
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()

    def parse(self, packet):
        super(TrustSignature, self).parse(packet)
        self.level = packet[:1]
        del packet[:1]
        self.amount = packet[:1]
        del packet[:1]


class RegularExpression(Signature):
    __slots__ = ['_regex']
    __typeid__ = 0x06

    @TypedProperty
    def regex(self):
        return self._regex
    @regex.str
    def regex(self, val):
        self._regex = val
    @regex.bytearray
    @regex.bytes
    def regex(self, val):
        self.regex = val.decode()

    def __init__(self):
        super(RegularExpression, self).__init__()
        self.regex = r''

    def __bytes__(self):
        _bytes = super(RegularExpression, self).__bytes__()
        _bytes += self.regex.encode()
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()

    def parse(self, packet):
        super(RegularExpression, self).parse(packet)
        self.regex = packet[:(self.header.length - 1)]
        del packet[:(self.header.length - 1)]


class Revocable(Signature):
    __slots__ = ['_revocable']
    __typeid__ = 0x07

    @TypedProperty
    def revocable(self):
        return self._revocable
    @revocable.bool
    def revocable(self, val):
        self._revocable = val
    @revocable.bytearray
    @revocable.bytes
    def revocable(self, val):
        self.revocable = bool(self.bytes_to_int(val))

    def __init__(self):
        super(Revocable, self).__init__()
        self.revocable = False

    def __bytes__(self):
        _bytes = super(Revocable, self).__bytes__()
        _bytes += self.int_to_bytes(int(self.revocable))
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()

    def parse(self, packet):
        super(Revocable, self).parse(packet)
        self.revocable = packet[:1]
        del packet[:1]


class KeyExpirationTime(SignatureExpirationTime):
    __slots__ = []
    __typeid__ = 0x09

    def __pgpdump__(self):
        raise NotImplementedError()


class PreferredSymmetricAlgorithms(FlagList):
    __slots__ = []
    __typeid__ = 0x0B
    __flags__ = SymmetricKeyAlgorithm

    def __pgpdump__(self):
        raise NotImplementedError()


class RevocationKey(Signature):
    __slots__ = ['_keyclass', '_algorithm', '_fingerprint']
    __typeid__ = 0x0C

    @TypedProperty
    def keyclass(self):
        return self._keyclass
    @keyclass.list
    def keyclass(self, val):
        self._keyclass = val
    @keyclass.RevocationKeyClass
    def keyclass(self, val):
        self.keyclass.append(val)
    @keyclass.int
    def keyclass(self, val):
        self.keyclass += RevocationKeyClass & val
    @keyclass.bytearray
    @keyclass.bytes
    def keyclass(self, val):
        self.keyclass = self.bytes_to_int(val)

    @TypedProperty
    def algorithm(self):
        return self._algorithm
    @algorithm.PubKeyAlgorithm
    def algorithm(self, val):
        self._algorithm = val
    @algorithm.int
    def algorithm(self, val):
        self.algorithm = PubKeyAlgorithm(val)
    @algorithm.bytearray
    @algorithm.bytes
    def algorithm(self, val):
        self.algorithm = self.bytes_to_int(val)

    @TypedProperty
    def fingerprint(self):
        return self._fingerprint
    @fingerprint.Fingerprint
    def fingerprint(self, val):
        self._fingerprint = val
    @fingerprint.str
    def fingerprint(self, val):
        self.fingerprint = Fingerprint(val)
    @fingerprint.bytearray
    @fingerprint.bytes
    def fingerprint(self, val):
        self.fingerprint = ''.join(['{:02x}'.format(c) for c in val]).upper()

    def __init__(self):
        super(RevocationKey, self).__init__()
        self.keyclass = []
        self.algorithm = PubKeyAlgorithm.Invalid
        self._fingerprint = ""

    def __bytes__(self):
        _bytes = super(RevocationKey, self).__bytes__()
        _bytes += self.int_to_bytes(sum(self.keyclass))
        _bytes += self.int_to_bytes(self.algorithm.value)
        _bytes += self.int_to_bytes(int(self.fingerprint), 20)
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()

    def parse(self, packet):
        super(RevocationKey, self).parse(packet)
        self.keyclass = packet[:1]
        del packet[:1]
        self.algorithm = packet[:1]
        del packet[:1]
        self.fingerprint = packet[:20]
        del packet[:20]


class Issuer(Signature):
    __slots__ = ['_issuer']
    __typeid__ = 0x10

    @TypedProperty
    def issuer(self):
        return self._issuer
    @issuer.bytearray
    @issuer.bytes
    def issuer(self, val):
        ##TODO: parse this properly
        self._issuer = val

    def __bytes__(self):
        _bytes = super(Issuer, self).__bytes__()
        _bytes += self._issuer
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()

    def parse(self, packet):
        super(Issuer, self).parse(packet)
        self.issuer = packet[:(self.header.length - 1)]
        del packet[:(self.header.length - 1)]


class NotationData(Signature):
    __slots__ = ['_flags', '_name', '_value']
    __typeid__ = 0x14

    @TypedProperty
    def flags(self):
        return self._flags
    @flags.list
    def flags(self, val):
        self._flags = val
    @flags.NotationDataFlags
    def flags(self, val):
        self.flags.append(val)
    @flags.int
    def flags(self, val):
        self.flags += NotationDataFlags & val
    @flags.bytearray
    @flags.bytes
    def flags(self, val):
        self.flags = self.bytes_to_int(val)

    @TypedProperty
    def name(self):
        return self._name
    @name.str
    def name(self, val):
        self._name = val
    @name.bytearray
    @name.bytes
    def name(self, val):
        self.name = val.decode()

    @TypedProperty
    def value(self):
        return self._value
    @value.str
    def value(self, val):
        self._value = val
    @value.bytearray
    @value.bytes
    def value(self, val):
        if NotationDataFlags.HumanReadable in self.flags:
            self.value = val.decode()

        else:
            self._value = val

    def __init__(self):
        super(NotationData, self).__init__()
        self.flags = [0, 0, 0, 0]
        self.name = ""
        self.value = ""

    def __bytes__(self):
        _bytes = super(NotationData, self).__bytes__()
        _bytes += self.int_to_bytes(sum(self.flags)) + b'\x00\x00\x00'
        _bytes += self.int_to_bytes(len(self.name), 2)
        _bytes += self.int_to_bytes(len(self.value), 2)
        _bytes += self.name.encode()
        _bytes += self.value if isinstance(self.value, (bytearray, bytes)) else self.value.encode()
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()

    def parse(self, packet):
        super(NotationData, self).parse(packet)
        self.flags = packet[:1]
        del packet[:4]
        nlen = self.bytes_to_int(packet[:2])
        del packet[:2]
        vlen = self.bytes_to_int(packet[:2])
        del packet[:2]
        self.name = packet[:nlen]
        del packet[:nlen]
        self.value = packet[:vlen]
        del packet[:vlen]


class PreferredHashAlgorithms(FlagList):
    __slots__ = []
    __typeid__ = 0x15
    __flags__ = HashAlgorithm

    def __pgpdump__(self):
        raise NotImplementedError()


class PreferredCompressionAlgorithms(FlagList):
    __slots__ = []
    __typeid__ = 0x16
    __flags__ = CompressionAlgorithm

    def __pgpdump__(self):
        raise NotImplementedError()


class KeyServerPreferences(FlagList):
    __slots__ = []
    __typeid__ = 0x17
    __flags__ = _KeyServerPreferences

    def __pgpdump__(self):
        raise NotImplementedError()


class PreferredKeyServer(URI):
    __slots__ = []
    __typeid__ = 0x18

    def __pgpdump__(self):
        raise NotImplementedError()


class PrimaryUserID(Signature):
    __slots__ = ['_primary']
    __typeid__ = 0x19

    @TypedProperty
    def primary(self):
        return self._primary
    @primary.bool
    def primary(self, val):
        self._primary = val
    @primary.bytearray
    @primary.bytes
    def primary(self, val):
        self.primary = bool(self.bytes_to_int(val))

    def __init__(self):
        super(PrimaryUserID, self).__init__()
        self.primary = True

    def __bytes__(self):
        _bytes = super(PrimaryUserID, self).__bytes__()
        _bytes += self.int_to_bytes(int(self.primary))
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()

    def parse(self, packet):
        super(PrimaryUserID, self).parse(packet)
        self.primary = packet[:1]
        del packet[:1]


class Policy(URI):
    __slots__ = []
    __typeid__ = 0x1a

    def __pgpdump__(self):
        raise NotImplementedError()


class KeyFlags(ByteFlag):
    __slots__ = []
    __typeid__ = 0x1B
    __flags__ = _KeyFlags

    def __pgpdump__(self):
        raise NotImplementedError()


class SignersUserID(Signature):
    __slots__ = ['_userid']
    __typeid__ = 0x1C

    @TypedProperty
    def userid(self):
        return self._userid
    @userid.str
    def userid(self, val):
        self._userid = val
    @userid.bytearray
    @userid.bytes
    def userid(self, val):
        self.userid = val.decode()

    def __init__(self):
        super(SignersUserID, self).__init__()
        self.userid = ""

    def __bytes__(self):
        _bytes = super(SignersUserID, self).__bytes__()
        _bytes += self.userid.encode()
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()

    def parse(self, packet):
        super(SignersUserID, self).parse(packet)
        self.userid = packet[:(self.header.length - 1)]
        del packet[:(self.header.length - 1)]


class ReasonForRevocation(Signature):
    __slots__ = ['_code', '_string']
    __typeid__ = 0x1D

    @TypedProperty
    def code(self):
        return self._code
    @code.RevocationReason
    def code(self, val):
        self._code = val
    @code.int
    def code(self, val):
        self.code = RevocationReason(val)
    @code.bytearray
    @code.bytes
    def code(self, val):
        self.code = self.bytes_to_int(val)

    @TypedProperty
    def string(self):
        return self._string
    @string.str
    def string(self, val):
        self._string = val
    @string.bytearray
    @string.bytes
    def string(self, val):
        self.string = val.decode()

    def __init__(self):
        super(ReasonForRevocation, self).__init__()
        self.code = 0x00
        self.string = ""

    def __bytes__(self):
        _bytes = super(ReasonForRevocation, self).__bytes__()
        _bytes += self.int_to_bytes(self.code)
        _bytes += self.string.encode()
        return _bytes

    def __pgpdump__(self):
        raise NotImplementedError()

    def parse(self, packet):
        super(ReasonForRevocation, self).parse(packet)
        self.code = packet[:1]
        del packet[:1]
        self.string = packet[:(self.header.length - 2)]


class Features(ByteFlag):
    __typeid__ = 0x1E
    __flags__ = _Features

    def __pgpdump__(self):
        raise NotImplementedError()


##TODO: obtain subpacket type 0x1F - Signature Target


class EmbeddedSignature(Signature):
    ##TODO: this, once packet.packets.Signature is reworked
    # __slots__ = []
    # __typeid__ = 0x20
    pass