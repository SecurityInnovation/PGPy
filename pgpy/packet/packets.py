""" packet.py
"""
from .keyfields import RSASignature
from .keyfields import DSASignature
from .keyfields import ElGSignature

from .types import Packet
from .types import VersionedPacket

from ..constants import HashAlgorithm
from ..constants import PubKeyAlgorithm
from ..constants import SignatureType

from ..decorators import TypedProperty


class Signature(VersionedPacket):
    __typeid__ = 0x02

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

        elif val == PubKeyAlgorithm.ElGamal:
            self.signature = ElGSignature

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
        self.halg = HashAlgorithm(val)

    @property
    def signature(self):
        return self._signature
    @signature.setter
    def signature(self, val):
        self._signature = val

    def __init__(self):
        super(Signature, self).__init__()
        # v4-only fields
        self.subpackets = None

        # v3-only fields
        self.ctime = None
        self.signer = None
        self.lh = None

        # v4 and v3 fields
        self._sigtype = None
        self._pubalg = None
        self._halg = None
        self.signature = None

    def __bytes__(self):
        _bytes = bytearray()
        _bytes += super(Signature, self).__bytes__()

        def v4(_bytes):
            _bytes += self.int_to_bytes(self.sigtype)
            _bytes += self.int_to_bytes(self.pubalg)
            _bytes += self.int_to_bytes(self.halg)


        vs = 'v{:1d}'.format(self.version)
        if vs in locals() and callable(locals()[vs]):
            locals()[vs](_bytes)
            return bytes(_bytes)

        else:
            raise NotImplementedError()

    def parse(self, packet):
        super(Signature, self).parse(packet)

        def v4(packet):
            self.sigtype = packet[0]
            del packet[0]

            self.pubalg = packet[0]
            del packet[0]

            self.halg = packet[0]
            del packet[0]

            ##TODO: subpacketsssss
            ##TODO: signature MPI
            del packet[:self.header.length - 4]

        vs = 'v{:1d}'.format(self.version)
        if vs in locals() and callable(locals()[vs]):
            locals()[vs](packet)

        else:
            del packet[:self.header.length - 1]

# import abc
# import calendar
# import hashlib
#
# from datetime import datetime
# from enum import Enum
#
# from cryptography.exceptions import UnsupportedAlgorithm
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.ciphers import Cipher, modes
#
# # from .fields.fields import Header
# # from .fields.fields import SignatureSubPackets
# # from .fields.fields import UserAttributeSubPackets
# from .fields.keyfields import MPIFields
# from .fields.keyfields import String2Key
# from .types import HashAlgo
# from .types import PFIntEnum
# from .types import PubKeyAlgo
#
# from ..errors import PGPKeyDecryptionError
# from ..errors import PGPOpenSSLCipherNotSupported
#
# from ..types import PGPObject
#
# from ..util import bytes_to_int
# from ..util import int_to_bytes
#
#
# class PGPPacketClass(Enum):
#         # tag support list
#         # [ ] 0  - Reserved (Illegal Value)
#         # [ ] 1  - Public-Key Encrypted Session Key Packet
#         # [x] 2  - Signature Packet
#         # Signature = Header.Tag.Signature
#         # [ ] 3  - Symmetric-Key Encrypted Session Key Packet
#         # [ ] 4  - One-Pass Signature Packet
#         # [x] 5  - Secret-Key Packet
#         # PrivKey = Header.Tag.PrivKey
#         # [x] 6  - Public-Key Packet
#         # PubKey = Header.Tag.PubKey
#         # [x] 7  - Secret-Subkey Packet
#         # PrivSubKey = Header.Tag.PrivSubKey
#         # [ ] 8  - Compressed Data Packet
#         # [ ] 9  - Symmetrically Encrypted Data Packet
#         # [ ] 10 - Marker Packet
#         # [ ] 11 - Literal Data Packet
#         # [x] 12 - Trust Packet
#         # Trust = Header.Tag.Trust
#         # [x] 13 - User ID Packet
#         # UserID = Header.Tag.UserID
#         # [x] 14 - Public-Subkey Packet
#         # PubSubKey = Header.Tag.PubSubKey
#         # [x] 17 - User Attribute Packet
#         # UserAttribute = Header.Tag.UserAttribute
#         # [ ] 18 - Sym. Encrypted and Integrity Protected Data Packet
#         # [ ] 19 - Modification Detection Code Packet
#
#         @property
#         def subclass(self):
#             classes = {PGPPacketClass.Signature: Signature,
#                        PGPPacketClass.PubKey: PubKey,
#                        PGPPacketClass.PubSubKey: PubSubKey,
#                        PGPPacketClass.PrivKey: PrivKey,
#                        PGPPacketClass.PrivSubKey: PrivSubKey,
#                        PGPPacketClass.Trust: Trust,
#                        PGPPacketClass.UserID: UserID,
#                        PGPPacketClass.UserAttribute: UserAttribute}
#
#             if self in classes:
#                 return classes[self]
#
#             # the requested packet type is not directly supported
#             # so we'll treat it as opaque and move along
#             return OpaquePacket
#
#
# class Packet(PGPObject):
#     __metaclass__ = abc.ABCMeta
#
#     @staticmethod
#     def load_packet(packet):
#         h = Header()
#         h.parse(packet)
#
#         newpkt = PGPPacketClass(h.tag).subclass()
#         newpkt.parse(packet)
#
#         return newpkt
#
#     @abc.abstractproperty
#     def name(self):
#         """Packet name"""
#         return ""
#
#     def __init__(self):
#         super(Packet, self).__init__()
#         self.header = Header()
#
#     def parse(self, packet):
#         packet = self.header.parse(packet)
#         return packet
#         # return packet[len(self.header.__bytes__()):]
# # class Packet(object):
# #     name = ""
# #
# #     def __init__(self, packet=None, ptype=None):
# #         # __init__ on Packet is now a "factory" of sorts
# #         #   - if `packet` is None, this is to be a shiny new packet created by PGPy
# #         #     of type `type`
# #         #   - if `packet` is not None, this is an existing packet to be parsed
# #         #     `type` is ignored
# #         #
# #         # packet will be None if we're creating a new packet from scratch
# #         self.header = Header()
# #
# #         if packet is None and ptype is not None:
# #             self.header.tag = ptype
# #             self.__class__ = PGPPacketClass(ptype).subclass
# #             self.__class__.__init__(self)
# #
# #         # we're parsing an existing packet
# #         if packet is not None:
# #             # parse header, then change into our subclass
# #             self.header.parse(packet)
# #             self.__class__ = PGPPacketClass(self.header.tag).subclass
# #             self.__class__.__init__(self)
# #
# #             # get the current packet length from the header, then parse it
# #             start = len(self.header.__bytes__())
# #             end = start + self.header.length
# #             self.parse(packet[start:end])
# #
# #     def parse(self, packet):
# #         raise NotImplementedError(self.header.tag.name)  # pragma: no cover
# #
# #     def __bytes__(self):
# #         raise NotImplementedError(self.header.tag.name)  # pragma: no cover
# #
# #     def pgpdump_out(self):
# #         raise NotImplementedError(self.header.tag.name)  # pragma: no cover
#
#
# class OpaquePacket(Packet):
#     def __init__(self):
#         super(OpaquePacket, self).__init__()
#         self._data = b''
#
#     def parse(self, packet):
#         self._data = super(OpaquePacket, self).parse(packet)
#
#     def __bytes__(self):
#         return self.header.__bytes__() + self._data
#
#
# class Signature(Packet):
#     """
#     The body of a version 4 Signature packet contains:
#
#      - One-octet version number (4).
#
#      - One-octet signature type.
#
#      - One-octet public-key algorithm.
#
#      - One-octet hash algorithm.
#
#      - Two-octet scalar octet count for following hashed subpacket data.
#        Note that this is the length in octets of all of the hashed
#        subpackets; a pointer incremented by this number will skip over
#        the hashed subpackets.
#
#      - Hashed subpacket data set (zero or more subpackets).
#
#      - Two-octet scalar octet count for the following unhashed subpacket
#        data.  Note that this is the length in octets of all of the
#        unhashed subpackets; a pointer incremented by this number will
#        skip over the unhashed subpackets.
#
#      - Unhashed subpacket data set (zero or more subpackets).
#
#      - Two-octet field holding the left 16 bits of the signed hash
#        value.
#
#      - One or more multiprecision integers comprising the signature.
#        This portion is algorithm specific, as described above.
#
#     The concatenation of the data being signed and the signature data
#     from the version number through the hashed subpacket data (inclusive)
#     is hashed.  The resulting hash value is what is signed.  The left 16
#     bits of the hash are included in the Signature packet to provide a
#     quick test to reject some invalid signatures.
#
#     There are two fields consisting of Signature subpackets.  The first
#     field is hashed with the rest of the signature data, while the second
#     is unhashed.  The second set of subpackets is not cryptographically
#     protected by the signature and should include only advisory
#     information.
#     """
#     class Version(PFIntEnum):
#         v4 = 4
#
#
#         def __str__(self):
#             types = {self.BinaryDocument: "Signature of a binary document",
#                      self.CanonicalDocument: "Signature of a canonical text document",
#                      self.Standalone: "Standalone signature",
#                      self.Generic_UserID_Pubkey: "Generic certification of a User ID and Public Key packet",
#                      self.Persona_UserID_Pubkey: "Persona certification of a User ID and Public-Key packet",
#                      self.Casual_UserID_Pubkey: "Casual certification of a User ID and Public-Key packet",
#                      self.Positive_UserID_Pubkey: "Positive certification of a User ID and Public Key packet",
#                      self.Subkey_Binding: "Subkey Binding Signature",
#                      self.PrimaryKey_Binding: "Primary Key Binding Signature",
#                      self.DirectlyOnKey: "Signature directly on a key",
#                      self.KeyRevocation: "Key revocation signature",
#                      self.SubkeyRevocation: "Subkey revocation signature",
#                      self.CertRevocation: "Certification revocation signature",
#                      self.Timestamp: "Timestamp signature",
#                      self.ThirdParty_Confirmation: "Third-Party Confirmation signature"}
#
#             if self in types:
#                 return types[self]
#
#             raise NotImplementedError(self.name)  # pragma: no cover
#
#     @property
#     def name(self):
#         return "Signature Packet"
#
#     @property
#     def magic(self):
#         return "SIGNATURE"
#
#     def __init__(self):
#         super(Signature, self).__init__()
#         self.version = Signature.Version.v4  # default for new Signature packets
#         self.type = Signature.Type.BinaryDocument  # default for new Signature packets
#         self.key_algorithm = PubKeyAlgo.RSAEncryptOrSign  # default for new Signature packets
#         self.hash_algorithm = 0
#         self.hashed_subpackets = SignatureSubPackets()
#         self.hashed_subpackets.hashed = True
#         self.unhashed_subpackets = SignatureSubPackets()
#         self.hash2 = b''
#         self.signature = MPIFields()
#
#     def parse(self, packet):
#         packet = super(Signature, self).parse(packet)
#
#         self.version = Signature.Version(bytes_to_int(packet[:1]))
#         packet = packet[1:]
#
#         self.type = Signature.Type(bytes_to_int(packet[:1]))
#         packet = packet[1:]
#
#         self.key_algorithm = PubKeyAlgo(bytes_to_int(packet[:1]))
#         packet = packet[1:]
#
#         self.hash_algorithm = HashAlgo(bytes_to_int(packet[:1]))
#         packet = packet[1:]
#
#         # subpackets
#         packet = self.hashed_subpackets.parse(packet)
#
#         packet = self.unhashed_subpackets.parse(packet)
#
#         # hash2
#         self.hash2 = packet[:2]
#         packet = packet[2:]
#
#         # algorithm-specific integer(s)
#         packet = self.signature.parse(packet, self)
#         # packet = self.signature.parse(packet, self.header.tag, self.key_algorithm)
#
#         return packet
#
#     def __bytes__(self):
#         _bytes = b''
#         _bytes += self.header.__bytes__()
#         _bytes += self.version.__bytes__()
#         _bytes += self.type.__bytes__()
#         _bytes += self.key_algorithm.__bytes__()
#         _bytes += self.hash_algorithm.__bytes__()
#         _bytes += self.hashed_subpackets.__bytes__()
#         _bytes += self.unhashed_subpackets.__bytes__()
#         _bytes += self.hash2
#         _bytes += self.signature.sigbytes()
#         return _bytes
#
#     def __pgpdump__(self):
#         raise NotImplementedError()
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
