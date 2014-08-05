""" packet.py
"""
import calendar

from datetime import datetime

from .fields import SubPackets
from .fields import RSASignature
from .fields import DSASignature
from .fields import RSAPub
from .fields import DSAPub
from .fields import ElGPub

from .types import Packet
from .types import VersionedPacket

from ..constants import HashAlgorithm
from ..constants import PubKeyAlgorithm
from ..constants import SignatureType

from ..decorators import TypedProperty


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


class PrivKey(VersionedPacket):
    __typeid__ = 0x05
    __ver__ = 0


class PrivKeyV4(PrivKey):
    __ver__ = 4


class PubKey(VersionedPacket):
    __typeid__ = 0x06
    __ver__ = 0


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
            self.keymaterial = RSAPub()

        elif val == PubKeyAlgorithm.DSA:
            self.keymaterial = DSAPub()

        elif val == PubKeyAlgorithm.ElGamal:
            self.keymaterial = ElGPub()


    @pkalg.int
    def pkalg(self, val):
        self.pkalg = PubKeyAlgorithm(val)

    @property
    def keymaterial(self):
        return self._keymaterial
    @keymaterial.setter
    def keymaterial(self, val):
        self._keymaterial = val

    def __init__(self):
        super(PubKeyV4, self).__init__()
        self.created = datetime.utcnow()
        self.pkalg = 0
        self.keymaterial = None

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += super(PubKeyV4, self).__bytes__()
        _bytes += self.int_to_bytes(calendar.timegm(self.created.timetuple()), 4)
        _bytes += self.int_to_bytes(self.pkalg)
        _bytes += self.keymaterial.__bytes__()
        return bytes(_bytes)

    def parse(self, packet):
        super(PubKeyV4, self).parse(packet)

        self.created = packet[:4]
        del packet[:4]

        self.pkalg = packet[0]
        del packet[0]

        self.keymaterial.parse(packet)


class PrivSubKey(VersionedPacket):
    __typeid__ = 0x07
    __ver__ = 0


class PrivSubKeyV4(PrivSubKey, PrivKeyV4):
    __ver__ = 4


class PubSubKey(VersionedPacket):
    __typeid__ = 0x0E
    __ver__ = 0


class PubSubKeyV4(PubSubKey, PubKeyV4):
    __ver__ = 4


#
#
# class KeyPacket(Packet):
#     class Version(PFIntEnum):
#         v4 = 4
#
#     @property
#     def fingerprint(self):
#         ##TODO: use _Fingerprint which is currently defined in pgpy.keys.KeyCollection
#         ##      but will be moved to pgpy.types
#         if self._fp is None:
#             # We have not yet computed the fingerprint, so we'll have to do that now.
#             # Here is the RFC 4880 section on computing v4 fingerprints:
#             #
#             # A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
#             # followed by the two-octet packet length, followed by the entire
#             # Public-Key packet starting with the version field.  The Key ID is the
#             # low-order 64 bits of the fingerprint.
#             sha1 = hashlib.sha1()
#             bcde_len = int_to_bytes(6 + len(self.key_material.pubbytes()), 2)
#
#             # a.1) 0x99 (1 octet)
#             sha1.update(b'\x99')
#             # a.2 high-order length octet
#             sha1.update(bcde_len[:1])
#             # a.3 low-order length octet
#             sha1.update(bcde_len[-1:])
#             # b) version number = 4 (1 octet);
#             sha1.update(b'\x04')
#             # c) timestamp of key creation (4 octets);
#             sha1.update(int_to_bytes(calendar.timegm(self.key_creation.timetuple()), 4))
#             # d) algorithm (1 octet): 17 = DSA (example);
#             sha1.update(self.key_algorithm.__bytes__())
#             # e) Algorithm-specific fields.
#             sha1.update(self.key_material.pubbytes())
#
#             # now store the digest
#             self._fp = sha1.hexdigest().upper()
#
#         return self._fp
#
#     def __init__(self):
#         super(KeyPacket, self).__init__()
#         self._fp = None
#
#         self.version = KeyPacket.Version.v4  # default for new Key packets
#         self.key_creation = datetime.utcnow()
#         self.key_algorithm = PubKeyAlgo.RSAEncryptOrSign
#         self.key_material = MPIFields()
#
#     def parse(self, packet):
#         packet = super(KeyPacket, self).parse(packet)
#
#         # all keys have the public component, at least
#         self.version = PubKey.Version(bytes_to_int(packet[:1]))
#         packet = packet[1:]
#
#         self.key_creation = datetime.utcfromtimestamp(bytes_to_int(packet[:4]))
#         packet = packet[4:]
#
#         self.key_algorithm = PubKeyAlgo(bytes_to_int(packet[:1]))
#         packet = packet[1:]
#
#         packet = self.key_material.parse(packet, self)
#         return packet
#
#     def __bytes__(self):
#         _bytes = b''
#         _bytes += self.header.__bytes__()
#         _bytes += self.version.__bytes__()
#         _bytes += int_to_bytes(calendar.timegm(self.key_creation.timetuple()), 4)
#         _bytes += self.key_algorithm.__bytes__()
#         _bytes += self.key_material.pubbytes()
#         return _bytes
#
#
# class Public(KeyPacket):
#     pass
#
#
# class Private(KeyPacket):
#     @property
#     def encrypted(self):
#         return not self.stokey.id == 0
#
#     def __init__(self):
#         super(Private, self).__init__()
#         self.stokey = String2Key()
#         self.enc_seckey_material = b''
#         self.checksum = b''
#
#     def parse(self, packet):
#         # can't use super here, or it traverses the inheritance tree weirdly
#         packet = KeyPacket.parse(self, packet)
#         packet = self.stokey.parse(packet)
#
#         # secret key material is not encrypted
#         if self.stokey.id == 0:
#             packet = self.key_material.parse(packet, self, sec=True)
#
#         # secret key material is encrypted
#         else:
#             mend = (self.header.length - (len(self.__bytes__()) - len(self.header.__bytes__()))) -  2
#             if self.stokey.id == 254:
#                 mend += 2
#
#             self.enc_seckey_material = packet[:mend]
#             packet = packet[mend:]
#
#         if self.stokey.id in [0, 255]:
#             self.checksum = packet[:2]
#             packet = packet[2:]
#
#         return packet
#
#     def __bytes__(self):
#         _bytes = super(Private, self).__bytes__()
#         _bytes += self.stokey.__bytes__()
#         if self.stokey.id == 0:
#             _bytes += self.key_material.privbytes()
#         else:
#             _bytes += self.enc_seckey_material
#         _bytes += self.checksum
#         return _bytes
#
#     def encrypt_keymaterial(self, passphrase):
#         ##TODO: encrypt secret key material that is not yet encrypted
#         ##TODO: generate String2Key specifier for newly encrypted data
#         pass
#
#     def decrypt_keymaterial(self, passphrase):
#         if not self.encrypted:
#             return  # pragma: no cover
#
#         # Encryption/decryption of the secret data is done in CFB mode using
#         # the key created from the passphrase and the Initial Vector from the
#         # packet.  A different mode is used with V3 keys (which are only RSA)
#         # than with other key formats.  (...)
#         #
#         # With V4 keys, a simpler method is used.  All secret MPI values are
#         # encrypted in CFB mode, including the MPI bitcount prefix.
#
#         # derive a key from our passphrase. If the passphrase is correct, this will be the right one...
#         sessionkey = self.stokey.derive_key(passphrase)
#
#         # attempt to decrypt this key!
#         cipher = Cipher(self.stokey.alg.decalg(sessionkey), modes.CFB(self.stokey.iv), backend=default_backend())
#         try:
#             decryptor = cipher.decryptor()
#
#         except UnsupportedAlgorithm as e:
#             raise PGPOpenSSLCipherNotSupported(str(e))
#
#         pt = decryptor.update(self.enc_seckey_material) + decryptor.finalize()
#
#         # check the hash to see if we decrypted successfully or not
#         if self.stokey.id == 254:
#             if not pt[-20:] == hashlib.new('sha1', pt[:-20]).digest():
#                 raise PGPKeyDecryptionError("Passphrase was incorrect!")
#
#             # parse decrypted key material into self.key_material
#             self.key_material.parse(pt[:-20], self.header.tag, self.key_algorithm, sec=True)
#             self.checksum = pt[-20:]
#
#     def undecrypt_keymaterial(self):
#         if self.encrypted and not self.key_material.privempty:
#             self.key_material.reset()
#             self.checksum = b''
#
#
# class Primary(KeyPacket):
#     pass
#
#
# class Sub(KeyPacket):
#     pass
#
#
# class PubKey(Primary, Public):
#     # Tag 6
#     name = 'Public Key Packet'
#
#     @property
#     def magic(self):
#         return "PUBLIC KEY PACKET"
#
#     def __pgpdump__(self):
#         raise NotImplementedError()
#
#
# class PubSubKey(Sub, Public):
#     # Tag 14
#     name = 'Public Subkey Packet'
#
#     magic = PubKey.magic
#
#     def __pgpdump__(self):
#         raise NotImplementedError()
#
#
# class PrivKey(Primary, Private):
#     # Tag 5
#     name = 'Secret Key Packet'
#
#     @property
#     def magic(self):
#         return "PRIVATE KEY PACKET"
#
#     def __pgpdump__(self):
#         raise NotImplementedError()
#
#
# class PrivSubKey(Sub, Private):
#     name = 'Secret Subkey Packet'
#
#     magic = PrivKey.magic
#
#     def __pgpdump__(self):
#         raise NotImplementedError()
#
# class UserID(Packet):
#     name = "User ID Packet"
#
#     @property
#     def magic(self):
#         raise NotImplementedError()
#
#     def __init__(self):
#         super(UserID, self).__init__()
#         self.data = b''
#
#     def parse(self, packet):
#         packet = super(UserID, self).parse(packet)
#         self.data = packet[:self.header.length]
#         return packet[self.header.length:]
#
#     def __bytes__(self):
#         _bytes = b''
#         _bytes += self.header.__bytes__()
#         _bytes += self.data
#
#         return _bytes
#
#     def __pgpdump__(self):
#         raise NotImplementedError()
#
#
# class Trust(Packet):
#     name = "Trust Packet"
#
#     class TrustLevel(PFIntEnum):
#         # trust levels
#         Unknown = 0
#         Expired = 1
#         Undefined = 2
#         Never = 3
#         Marginal = 4
#         Fully = 5
#         Ultimate = 6
#
#     class TrustFlags(PFIntEnum):
#         Revoked = 32
#         SubRevoked = 64
#         Disabled = 128
#         PendingCheck = 256
#
#     @property
#     def trust(self):
#         return int_to_bytes(self.trustlevel + sum(self.trustflags), 2)
#
#     def __init__(self):
#         self.trustlevel = Trust.TrustLevel.Unknown
#         self.trustflags = []
#
#     def parse(self, packet):
#         # Trust packets contain data that record the user's
#         # specifications of which key holders are trustworthy introducers,
#         # along with other information that implementing software uses for
#         # trust information.  The format of Trust packets is defined by a given
#         # implementation.
#         # self.trust = packet
#
#         # GPG Trust packet format - see https://github.com/Commod0re/PGPy/issues/14
#         self.trustlevel = Trust.TrustLevel(bytes_to_int(packet) % 0xF)
#         for tf in sorted(Trust.TrustFlags.__members__.values()):
#             if bytes_to_int(packet) & tf.value:
#                 self.trustflags.append(tf.value)
#
#     def __bytes__(self):
#         _bytes = b''
#         _bytes += self.header.__bytes__()
#         _bytes += self.trust
#
#         return _bytes
#
#
# class UserAttribute(Packet):
#     """
#     5.12.  User Attribute Packet (Tag 17)
#
#     The User Attribute packet is a variation of the User ID packet.  It
#     is capable of storing more types of data than the User ID packet,
#     which is limited to text.  Like the User ID packet, a User Attribute
#     packet may be certified by the key owner ("self-signed") or any other
#     key owner who cares to certify it.  Except as noted, a User Attribute
#     packet may be used anywhere that a User ID packet may be used.
#
#     While User Attribute packets are not a required part of the OpenPGP
#     standard, implementations SHOULD provide at least enough
#     compatibility to properly handle a certification signature on the
#     User Attribute packet.  A simple way to do this is by treating the
#     User Attribute packet as a User ID packet with opaque contents, but
#     an implementation may use any method desired.
#
#     The User Attribute packet is made up of one or more attribute
#     subpackets.  Each subpacket consists of a subpacket header and a
#     body.  The header consists of:
#
#      - the subpacket length (1, 2, or 5 octets)
#
#      - the subpacket type (1 octet)
#
#     and is followed by the subpacket specific data.
#
#     The only currently defined subpacket type is 1, signifying an image.
#     An implementation SHOULD ignore any subpacket of a type that it does
#     not recognize.  Subpacket types 100 through 110 are reserved for
#     private or experimental use.
#     """
#     name = "User Attribute Packet"
#
#     @property
#     def magic(self):
#         raise NotImplementedError()
#
#     def __init__(self):
#         super(UserAttribute, self).__init__()
#         self.subpackets = UserAttributeSubPackets()
#
#     def parse(self, packet):
#         packet = super(UserAttribute, self).parse(packet)
#
#         while len(self.subpackets.__bytes__()) < self.header.length:
#             packet = self.subpackets.parse(packet)
#
#         return packet
#
#     def __bytes__(self):
#         _bytes = b''
#         _bytes += self.header.__bytes__()
#         _bytes += self.subpackets.__bytes__()
#         return _bytes
#
#     def __pgpdump__(self):
#         raise NotImplementedError
