""" packet.py
"""
import abc
import calendar
import hashlib
import re

from datetime import datetime

from .fields import DSAPriv
from .fields import DSAPub
from .fields import DSASignature
from .fields import ElGPriv
from .fields import ElGPub
from .fields import RSAPriv
from .fields import RSAPub
from .fields import RSASignature
from .fields import SubPackets
from .fields import UserAttributeSubPackets

from .types import Packet
from .types import VersionedPacket

from ..constants import HashAlgorithm
from ..constants import PubKeyAlgorithm
from ..constants import SignatureType
from ..constants import TrustFlags
from ..constants import TrustLevel

from ..decorators import TypedProperty

from ..types import Fingerprint


# Placeholder for 0x01


class Signature(VersionedPacket):
    __typeid__ = 0x02
    __ver__ = 0


class SignatureV4(Signature):
    """
    5.2.3.  Version 4 Signature Packet Format

    The body of a version 4 Signature packet contains:

     - One-octet version number (4).

     - One-octet signature type.

     - One-octet public-key algorithm.

     - One-octet hash algorithm.

     - Two-octet scalar octet count for following hashed subpacket data.
       Note that this is the length in octets of all of the hashed
       subpackets; a pointer incremented by this number will skip over
       the hashed subpackets.

     - Hashed subpacket data set (zero or more subpackets).

     - Two-octet scalar octet count for the following unhashed subpacket
       data.  Note that this is the length in octets of all of the
       unhashed subpackets; a pointer incremented by this number will
       skip over the unhashed subpackets.

     - Unhashed subpacket data set (zero or more subpackets).

     - Two-octet field holding the left 16 bits of the signed hash
       value.

     - One or more multiprecision integers comprising the signature.
       This portion is algorithm specific, as described above.

    The concatenation of the data being signed and the signature data
    from the version number through the hashed subpacket data (inclusive)
    is hashed.  The resulting hash value is what is signed.  The left 16
    bits of the hash are included in the Signature packet to provide a
    quick test to reject some invalid signatures.

    There are two fields consisting of Signature subpackets.  The first
    field is hashed with the rest of the signature data, while the second
    is unhashed.  The second set of subpackets is not cryptographically
    protected by the signature and should include only advisory
    information.

    The algorithms for converting the hash function result to a signature
    are described in a section below.
    """
    __typeid__ = 0x02
    __ver__ = 4

    @TypedProperty
    def sigtype(self):
        return self._sigtype
    @sigtype.SignatureType
    def sigtype(self, val):
        self._sigtype = val
    @sigtype.int
    def sigtype(self, val):
        self.sigtype = SignatureType(val)

    @TypedProperty
    def pubalg(self):
        return self._pubalg
    @pubalg.PubKeyAlgorithm
    def pubalg(self, val):
        self._pubalg = val
        if val in [PubKeyAlgorithm.RSAEncryptOrSign, PubKeyAlgorithm.RSAEncrypt, PubKeyAlgorithm.RSASign]:
            self.signature = RSASignature()

        elif val == PubKeyAlgorithm.DSA:
            self.signature = DSASignature()
    @pubalg.int
    def pubalg(self, val):
        self.pubalg = PubKeyAlgorithm(val)

    @TypedProperty
    def halg(self):
        return self._halg
    @halg.HashAlgorithm
    def halg(self, val):
        self._halg = val
    @halg.int
    def halg(self, val):
        try:
            self.halg = HashAlgorithm(val)

        except ValueError:
            self._halg = val

    @property
    def signature(self):
        return self._signature
    @signature.setter
    def signature(self, val):
        self._signature = val

    def __init__(self):
        super(Signature, self).__init__()
        self._sigtype = None
        self._pubalg = None
        self._halg = None
        self.subpackets = SubPackets()
        self.hleft = bytearray(2)
        self.signature = None

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += super(Signature, self).__bytes__()
        _bytes += self.int_to_bytes(self.sigtype)
        _bytes += self.int_to_bytes(self.pubalg)
        _bytes += self.int_to_bytes(self.halg)
        _bytes += self.subpackets.__bytes__()
        _bytes += self.hleft
        _bytes += self.signature.__bytes__()

        return bytes(_bytes)

    def parse(self, packet):
        super(Signature, self).parse(packet)
        self.sigtype = packet[0]
        del packet[0]

        self.pubalg = packet[0]
        del packet[0]

        self.halg = packet[0]
        del packet[0]

        self.subpackets.parse(packet)

        self.hleft = packet[:2]
        del packet[:2]

        self.signature.parse(packet)


# Placeholder for 0x03
# Placeholder for 0x04


class PrivKey(VersionedPacket):
    __typeid__ = 0x05
    __ver__ = 0


class PubKey(VersionedPacket):
    __typeid__ = 0x06
    __ver__ = 0

    @abc.abstractproperty
    def fingerprint(self):
        return ""


class PubKeyV4(PubKey):
    __ver__ = 4

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

    @TypedProperty
    def pkalg(self):
        return self._pkalg
    @pkalg.PubKeyAlgorithm
    def pkalg(self, val):
        self._pkalg = val

        if val in [PubKeyAlgorithm.RSASign, PubKeyAlgorithm.RSAEncrypt, PubKeyAlgorithm.RSAEncryptOrSign]:
            self.pubmaterial = RSAPub()
            if hasattr(self, 'secmaterial'):
                self.secmaterial = RSAPriv()

        elif val == PubKeyAlgorithm.DSA:
            self.pubmaterial = DSAPub()
            if hasattr(self, 'secmaterial'):
                self.secmaterial = DSAPriv()

        elif val in [PubKeyAlgorithm.ElGamal, PubKeyAlgorithm.FormerlyElGamalEncryptOrSign]:
            self.pubmaterial = ElGPub()
            if hasattr(self, 'secmaterial'):
                self.secmaterial = ElGPriv()
    @pkalg.int
    def pkalg(self, val):
        self.pkalg = PubKeyAlgorithm(val)

    @property
    def fingerprint(self):
        # A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
        # followed by the two-octet packet length, followed by the entire
        # Public-Key packet starting with the version field.  The Key ID is the
        # low-order 64 bits of the fingerprint.
        fp = hashlib.new('sha1')
        bcde_len = self.int_to_bytes(6 + len(self.pubmaterial.__bytes__()), 2)

        # a.1) 0x99 (1 octet)
        # a.2) high-order length octet
        # a.3) low-order length octet
        fp.update(b'\x99' + bcde_len[:1] + bcde_len[-1:])
        # b) version number = 4 (1 octet);
        fp.update(b'\x04')
        # c) timestamp of key creation (4 octets);
        fp.update(self.int_to_bytes(calendar.timegm(self.created.timetuple()), 4))
        # d) algorithm (1 octet): 17 = DSA (example);
        fp.update(self.int_to_bytes(self.pkalg))
        # e) Algorithm-specific fields.
        fp.update(self.pubmaterial.__bytes__())

        # and return the digest
        return Fingerprint(fp.hexdigest().upper())


    def __init__(self):
        super(PubKeyV4, self).__init__()
        self.created = datetime.utcnow()
        self.pkalg = 0
        self.pubmaterial = None

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += super(PubKeyV4, self).__bytes__()
        _bytes += self.int_to_bytes(calendar.timegm(self.created.timetuple()), 4)
        _bytes += self.int_to_bytes(self.pkalg)
        _bytes += self.pubmaterial.__bytes__()
        return bytes(_bytes)

    def parse(self, packet):
        super(PubKeyV4, self).parse(packet)

        self.created = packet[:4]
        del packet[:4]

        self.pkalg = packet[0]
        del packet[0]

        self.pubmaterial.parse(packet)


class PrivKeyV4(PrivKey, PubKeyV4):
    __ver__ = 4

    def __init__(self):
        super(PrivKeyV4, self).__init__()
        self.secmaterial = None

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += super(PrivKeyV4, self).__bytes__()
        _bytes += self.secmaterial.__bytes__()

        return bytes(_bytes)

    def parse(self, packet):
        super(PrivKeyV4, self).parse(packet)

        pend = self.header.length - (6 + len(self.pubmaterial))
        # temporary test
        assert (1 + 4 + 1 + len(self.pubmaterial) + pend) == self.header.length

        self.secmaterial.parse(packet[:pend])
        # since packet[:pend] is a *copy* of the first `pend` bytes of packet, we have to delete the real thing, too
        del packet[:pend]

    def unprotect(self, passphrase):
        self.secmaterial.decrypt_keyblob(passphrase)
        del passphrase


class PrivSubKey(VersionedPacket):
    __typeid__ = 0x07
    __ver__ = 0


class PrivSubKeyV4(PrivSubKey, PrivKeyV4):
    __ver__ = 4


# Placeholder for 0x08
# Placehlder for 0x09
# Placeholder for 0x0A
# Placeholder for 0x0B


class Trust(Packet):
    """
    5.10.  Trust Packet (Tag 12)

    The Trust packet is used only within keyrings and is not normally
    exported.  Trust packets contain data that record the user's
    specifications of which key holders are trustworthy introducers,
    along with other information that implementing software uses for
    trust information.  The format of Trust packets is defined by a given
    implementation.

    Trust packets SHOULD NOT be emitted to output streams that are
    transferred to other users, and they SHOULD be ignored on any input
    other than local keyring files.
    """
    __typeid__ = 0x0C

    @TypedProperty
    def trustlevel(self):
        return self._trustlevel
    @trustlevel.TrustLevel
    def trustlevel(self, val):
        self._trustlevel = val
    @trustlevel.int
    def trustlevel(self, val):
        self.trustlevel = TrustLevel(val & 0x0F)

    @TypedProperty
    def trustflags(self):
        return self._trustflags
    @trustflags.list
    def trustflags(self, val):
        self._trustflags = val
    @trustflags.int
    def trustflags(self, val):
        self._trustflags = TrustFlags & val

    def __init__(self):
        super(Trust, self).__init__()
        self.trustlevel = TrustLevel.Unknown
        self.trustflags = []

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += super(Trust, self).__bytes__()
        _bytes += self.int_to_bytes(self.trustlevel + sum(self.trustflags), 2)
        return bytes(_bytes)

    def parse(self, packet):
        super(Trust, self).parse(packet)
        # self.trustlevel = packet[0] & 0x1f
        t = self.bytes_to_int(packet[:2])
        del packet[:2]

        self.trustlevel = t
        self.flags = t


class UserID(Packet):
    """
    5.11.  User ID Packet (Tag 13)

    A User ID packet consists of UTF-8 text that is intended to represent
    the name and email address of the key holder.  By convention, it
    includes an RFC 2822 [RFC2822] mail name-addr, but there are no
    restrictions on its content.  The packet length in the header
    specifies the length of the User ID.
    """
    __typeid__ = 0x0D

    def __init__(self):
        super(UserID, self).__init__()
        self.name = ""
        self.comment = ""
        self.email = ""

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += super(UserID, self).__bytes__()
        _bytes += "{name:s}{comment:s}{email:s}".format(
            name=self.name,
            comment=" ({comment:s})".format(comment=self.comment) if self.comment not in [None, ""] else "",
            email=" <{email:s}>".format(email=self.email) if self.email not in [None, ""] else "").encode()
        return bytes(_bytes)

    def parse(self, packet):
        super(UserID, self).parse(packet)

        uid_text = packet[:self.header.length].decode('latin-1')
        del packet[:self.header.length]

        uid = re.match(r"""^
                           # name should always match something
                           (?P<name>[^\(<]*)
                           # comment *optionally* matches text in parens following name
                           # this should never come after email
                           (\ \((?P<comment>[^\)]+)\))?
                           # email *optionally* matches text in angle brackets following name or comment
                           # this should never come before a comment, if comment exists,
                           # but can immediately follow name if comment does not exist
                           (\ <(?P<email>[^>]+)>)?
                           $
                        """, uid_text, flags=re.VERBOSE).groupdict()

        self.name = uid['name']
        self.comment = uid['comment']
        self.email = uid['email']


class PubSubKey(VersionedPacket):
    __typeid__ = 0x0E
    __ver__ = 0


class PubSubKeyV4(PubSubKey, PubKeyV4):
    __ver__ = 4


class UserAttribute(Packet):
    """
    5.12.  User Attribute Packet (Tag 17)

    The User Attribute packet is a variation of the User ID packet.  It
    is capable of storing more types of data than the User ID packet,
    which is limited to text.  Like the User ID packet, a User Attribute
    packet may be certified by the key owner ("self-signed") or any other
    key owner who cares to certify it.  Except as noted, a User Attribute
    packet may be used anywhere that a User ID packet may be used.

    While User Attribute packets are not a required part of the OpenPGP
    standard, implementations SHOULD provide at least enough
    compatibility to properly handle a certification signature on the
    User Attribute packet.  A simple way to do this is by treating the
    User Attribute packet as a User ID packet with opaque contents, but
    an implementation may use any method desired.

    The User Attribute packet is made up of one or more attribute
    subpackets.  Each subpacket consists of a subpacket header and a
    body.  The header consists of:

     - the subpacket length (1, 2, or 5 octets)

     - the subpacket type (1 octet)

    and is followed by the subpacket specific data.

    The only currently defined subpacket type is 1, signifying an image.
    An implementation SHOULD ignore any subpacket of a type that it does
    not recognize.  Subpacket types 100 through 110 are reserved for
    private or experimental use.
    """
    __typeid__ = 0x11

    def __init__(self):
        super(UserAttribute, self).__init__()
        self.subpackets = UserAttributeSubPackets()

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += super(UserAttribute, self).__bytes__()
        _bytes += self.subpackets.__bytes__()
        return bytes(_bytes)

    def parse(self, packet):
        super(UserAttribute, self).parse(packet)
        while len(self.subpackets) < self.header.length:
            self.subpackets.parse(packet)

# Placeholder for 0x12
# Placeholder for 0x13
