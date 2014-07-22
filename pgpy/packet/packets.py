""" packet.py
"""
import abc
import calendar
import hashlib

from datetime import datetime
from enum import Enum

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from .fields.fields import Header
from .fields.fields import SignatureSubPackets
from .fields.fields import UserAttributeSubPackets
from .fields.keyfields import MPIFields
from .fields.keyfields import String2Key
from .types import HashAlgo
from .types import PFIntEnum
from .types import PubKeyAlgo

from ..errors import PGPKeyDecryptionError
from ..errors import PGPOpenSSLCipherNotSupported

from ..types import PGPObject

from ..util import bytes_to_int
from ..util import int_to_bytes


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

            # if self in [PGPPacketClass.PubKey, PGPPacketClass.PubSubKey]:
            if self == PGPPacketClass.PubKey:
                return PubKey

            if self == PGPPacketClass.PubSubKey:
                return PubSubKey

            if self == PGPPacketClass.PrivKey:
                return PrivKey

            if self == PGPPacketClass.PrivSubKey:
                return PrivSubKey

            if self == PGPPacketClass.Trust:
                return Trust

            if self == PGPPacketClass.UserID:
                return UserID

            if self == PGPPacketClass.UserAttribute:
                return UserAttribute

            raise NotImplementedError(self)  # pragma: no cover

class Packet(PGPObject):
    __metaclass__ = abc.ABCMeta

    @abc.abstractproperty
    def name(self):
        """Packet name"""
        return ""

    def __init__(self):
        super(Packet, self).__init__()
        self.header = Header()

    def parse(self, packet):
        self.header.parse(packet)
        return packet[len(self.header.__bytes__()):]
# class Packet(object):
#     name = ""
#
#     def __init__(self, packet=None, ptype=None):
#         # __init__ on Packet is now a "factory" of sorts
#         #   - if `packet` is None, this is to be a shiny new packet created by PGPy
#         #     of type `type`
#         #   - if `packet` is not None, this is an existing packet to be parsed
#         #     `type` is ignored
#         #
#         # packet will be None if we're creating a new packet from scratch
#         self.header = Header()
#
#         if packet is None and ptype is not None:
#             self.header.tag = ptype
#             self.__class__ = PGPPacketClass(ptype).subclass
#             self.__class__.__init__(self)
#
#         # we're parsing an existing packet
#         if packet is not None:
#             # parse header, then change into our subclass
#             self.header.parse(packet)
#             self.__class__ = PGPPacketClass(self.header.tag).subclass
#             self.__class__.__init__(self)
#
#             # get the current packet length from the header, then parse it
#             start = len(self.header.__bytes__())
#             end = start + self.header.length
#             self.parse(packet[start:end])
#
#     def parse(self, packet):
#         raise NotImplementedError(self.header.tag.name)  # pragma: no cover
#
#     def __bytes__(self):
#         raise NotImplementedError(self.header.tag.name)  # pragma: no cover
#
#     def pgpdump_out(self):
#         raise NotImplementedError(self.header.tag.name)  # pragma: no cover


class Signature(Packet):
    """
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
    """
    class Version(PFIntEnum):
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
            types = {self.BinaryDocument: "Signature of a binary document",
                     self.CanonicalDocument: "Signature of a canonical text document",
                     self.Standalone: "Standalone signature",
                     self.Generic_UserID_Pubkey: "Generic certification of a User ID and Public Key packet",
                     self.Persona_UserID_Pubkey: "Persona certification of a User ID and Public-Key packet",
                     self.Casual_UserID_Pubkey: "Casual certification of a User ID and Public-Key packet",
                     self.Positive_UserID_Pubkey: "Positive certification of a User ID and Public Key packet",
                     self.Subkey_Binding: "Subkey Binding Signature",
                     self.PrimaryKey_Binding: "Primary Key Binding Signature",
                     self.DirectlyOnKey: "Signature directly on a key",
                     self.KeyRevocation: "Key revocation signature",
                     self.SubkeyRevocation: "Subkey revocation signature",
                     self.CertRevocation: "Certification revocation signature",
                     self.Timestamp: "Timestamp signature",
                     self.ThirdParty_Confirmation: "Third-Party Confirmation signature"}

            if self in types:
                return types[self]

            raise NotImplementedError(self.name)  # pragma: no cover

    @property
    def name(self):
        return "Signature Packet"

    def __init__(self):
        super(Signature, self).__init__()
        self.version = Signature.Version.v4  # default for new Signature packets
        self.type = Signature.Type.BinaryDocument  # default for new Signature packets
        self.key_algorithm = PubKeyAlgo.RSAEncryptOrSign  # default for new Signature packets
        self.hash_algorithm = 0
        self.hashed_subpackets = SignatureSubPackets()
        self.hashed_subpackets.hashed = True
        self.unhashed_subpackets = SignatureSubPackets()
        self.hash2 = b''
        self.signature = MPIFields()

    def parse(self, packet):
        packet = super(Signature, self).parse(packet)

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


class KeyPacket(Packet):
    class Version(PFIntEnum):
        v4 = 4

    @property
    def fingerprint(self):
        ##TODO: use _Fingerprint which is currently defined in pgpy.keys.KeyCollection
        ##      but will be moved to pgpy.types
        if self._fp is None:
            # We have not yet computed the fingerprint, so we'll have to do that now.
            # Here is the RFC 4880 section on computing v4 fingerprints:
            #
            # A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
            # followed by the two-octet packet length, followed by the entire
            # Public-Key packet starting with the version field.  The Key ID is the
            # low-order 64 bits of the fingerprint.
            sha1 = hashlib.sha1()
            bcde_len = int_to_bytes(6 + len(self.key_material.pubbytes()), 2)

            # a.1) 0x99 (1 octet)
            sha1.update(b'\x99')
            # a.2 high-order length octet
            sha1.update(bcde_len[:1])
            # a.3 low-order length octet
            sha1.update(bcde_len[-1:])
            # b) version number = 4 (1 octet);
            sha1.update(b'\x04')
            # c) timestamp of key creation (4 octets);
            sha1.update(int_to_bytes(calendar.timegm(self.key_creation.timetuple()), 4))
            # d) algorithm (1 octet): 17 = DSA (example);
            sha1.update(self.key_algorithm.__bytes__())
            # e) Algorithm-specific fields.
            sha1.update(self.key_material.pubbytes())

            # now store the digest
            self._fp = sha1.hexdigest().upper()

        return self._fp

    def __init__(self):
        self._fp = None

        self.version = KeyPacket.Version.v4  # default for new Key packets
        self.key_creation = datetime.utcnow()
        self.key_algorithm = PubKeyAlgo.RSAEncryptOrSign
        self.key_material = MPIFields()

    def parse(self, packet):
        # all keys have the public component, at least
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


class Public(KeyPacket):
    pass


class Private(KeyPacket):
    @property
    def encrypted(self):
        return not self.stokey.id == 0

    def __init__(self):
        super(Private, self).__init__()
        self.stokey = String2Key()
        self.enc_seckey_material = b''
        self.checksum = b''

    def parse(self, packet):
        super(Private, self).parse(packet)
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
        _bytes = super(Private, self).__bytes__()
        _bytes += self.stokey.__bytes__()
        if self.stokey.id == 0:
            _bytes += self.key_material.privbytes()
        else:
            _bytes += self.enc_seckey_material
        _bytes += self.checksum
        return _bytes

    def encrypt_keymaterial(self, passphrase):
        ##TODO: encrypt secret key material that is not yet encrypted
        ##TODO: generate String2Key specifier for newly encrypted data
        pass

    def decrypt_keymaterial(self, passphrase):
        if not self.encrypted:
            return  # pragma: no cover

        # Encryption/decryption of the secret data is done in CFB mode using
        # the key created from the passphrase and the Initial Vector from the
        # packet.  A different mode is used with V3 keys (which are only RSA)
        # than with other key formats.  (...)
        #
        # With V4 keys, a simpler method is used.  All secret MPI values are
        # encrypted in CFB mode, including the MPI bitcount prefix.

        # derive a key from our passphrase. If the passphrase is correct, this will be the right one...
        sessionkey = self.stokey.derive_key(passphrase)

        # attempt to decrypt this key!
        cipher = Cipher(self.stokey.alg.decalg(sessionkey), modes.CFB(self.stokey.iv), backend=default_backend())
        try:
            decryptor = cipher.decryptor()

        except UnsupportedAlgorithm as e:
            raise PGPOpenSSLCipherNotSupported(str(e))

        pt = decryptor.update(self.enc_seckey_material) + decryptor.finalize()

        # check the hash to see if we decrypted successfully or not
        if self.stokey.id == 254:
            if not pt[-20:] == hashlib.new('sha1', pt[:-20]).digest():
                raise PGPKeyDecryptionError("Passphrase was incorrect!")

            # parse decrypted key material into self.key_material
            self.key_material.parse(pt[:-20], self.header.tag, self.key_algorithm, sec=True)
            self.checksum = pt[-20:]

    def undecrypt_keymaterial(self):
        if self.encrypted and not self.key_material.privempty:
            self.key_material.reset()
            self.checksum = b''


class Primary(KeyPacket):
    pass


class Sub(KeyPacket):
    pass


class PubKey(Primary, Public):
    # Tag 6
    name = 'Public Key Packet'


class PubSubKey(Sub, Public):
    # Tag 14
    name = 'Public Subkey Packet'


class PrivKey(Primary, Private):
    # Tag 5
    name = 'Secret Key Packet'


class PrivSubKey(Sub, Private):
    name = 'Secret Subkey Packet'


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
    name = "User Attribute Packet"

    def __init__(self):
        self.subpackets = UserAttributeSubPackets()

    def parse(self, packet):
        ##TODO: these are a separate set of subpackets from the usual subpackets
        ##      defined as User Attribute Subpackets. There is only one currently defined in the standard
        ##      but we should treat it the same way for later extensibility
        ##      for now, let's just store it, though
        # self.contents = packet
        self.subpackets.parse(packet)

    def __bytes__(self):
        _bytes = b''
        _bytes += self.header.__bytes__()
        _bytes += self.subpackets.__bytes__()
        return _bytes
