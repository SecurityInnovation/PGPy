""" pgp.py

this is where the armorable PGP block objects live
"""
from .types import Exportable
from .types import PGPObject


class PGPSignature(PGPObject, Exportable):
    pass


class PGPKey(PGPObject, Exportable):
    pass


# # import calendar
# # import re
# # from datetime import datetime
# #
# # from .packet.packets import Packet
# # from .packet.packets import Signature
# # from .packet.types import HashAlgo
# # from .packet.types import PubKeyAlgo
# #
# # # from .packet.fields.fields import Header
# #
# # from .errors import PGPError
# # from .types import FileLoader
# # from .types import PGPObject
# # from .util import int_to_bytes
# # from .util import is_ascii
#
#
# # def pgpload(pgpbytes):
# #     # load pgpbytes regardless of type, first
# #     f = FileLoader(pgpbytes)
# #
# #     b = []
# #
# #     # now, are there any ASCII PGP blocks at all?
# #     if is_ascii(f._bytes):
# #         # decode/parse ASCII PGP blocks
# #         nascii = list(re.finditer(ASCII_BLOCK, f.bytes.decode(), flags=re.MULTILINE | re.DOTALL))
# #
# #         if len(nascii) == 0:
# #             raise PGPError("No PGP blocks to read!")  # pragma: no cover
# #
# #         for block in nascii:
# #             if block.group(1)[-9:] == "KEY BLOCK":
# #                 c = PGPKey
# #
# #             if block.group(1) == "SIGNATURE":
# #                 c = PGPSignature
# #
# #             p = c(block.group(0).encode())
# #             p.path = f.path
# #             b.append(p)
# #
# #     # try to load binary instead
# #     else:
# #         block = PGPBlock(pgpbytes)
# #
# #         # is this a signature?
# #         if block.packets[0].header.tag.is_signature:
# #             b.append(PGPSignature(pgpbytes))
# #             block.packets = []
# #
# #         # now go through block and split out any keys, if possible
# #         bpos = 0
# #         for i, pkt in enumerate(block.packets):
# #             # if this is the last packet, we need to instantiate whatever type is at block.packets[bpos]
# #             if i == len(block.packets) - 1:
# #                 pktblock = block.packets[bpos:]
# #
# #                 if pktblock[0].header.tag.is_key and not pktblock[0].header.tag.is_subkey:
# #                     bl = PGPKey(None)
# #
# #                 bl.packets = pktblock
# #                 b.append(bl)
# #                 bpos = i
# #                 continue
# #
# #             # a public or private key (not subkey) indicates the start of a new block,
# #             # so load the previous block into a new object
# #             if i != bpos and pkt.header.tag.is_key and not pkt.header.tag.is_subkey:
# #                 pktblock = block.packets[bpos:i]
# #                 bl = PGPKey(None)
# #                 bl.packets = pktblock
# #
# #                 b.append(bl)
# #                 bpos = i
# #                 continue
# #
# #     ##TODO: load from a GPG agent
# #
# #     # return loaded blocks
# #     return b
#
#
# class PGPSignature(PGPObject):
#     """
#     Returned by :py:meth:`pgpy.PGPKeyring.sign`
#     """
#     # @property
#     # def sigpkt(self):
#     #     return self.packets[0]
#
#     # @classmethod
#     # def new(cls, keyid,
#     #         sigtype=Signature.Type.BinaryDocument,
#     #         alg=PubKeyAlgo.RSAEncryptOrSign,
#     #         hashalg=HashAlgo.SHA256):
#     #     # create a new signature
#     #     newsig = PGPSignature(None)
#     #
#     #     # create a new signature packet
#     #     newsig.packets = [Packet(ptype=Header.Tag.Signature)]
#     #     newsig.sigpkt.type = sigtype
#     #     newsig.sigpkt.key_algorithm = alg
#     #     newsig.sigpkt.hash_algorithm = hashalg
#     #
#     #     # add hashed subpacket - signature creation time
#     #     ##TODO: maybe use the subpacket type instead of \x02
#     #     ##TODO: implement subpacket creation in SubPackets
#     #     hspacket = b'\x00\x06\x05\x02' + int_to_bytes(calendar.timegm(datetime.utcnow().timetuple()), 4)
#     #     newsig.sigpkt.hashed_subpackets.parse(hspacket)
#     #
#     #     # add unhashed subpacket - issuer key ID
#     #     ##TODO: maybe use the subpacket type instead of \x10
#     #     ##TODO: implement subpacket creation in SubPackets
#     #     spacket = b'\x09\x10' + int_to_bytes(int(keyid, 16), 8)
#     #     spacket = int_to_bytes(len(spacket), 2) + spacket
#     #     newsig.sigpkt.unhashed_subpackets.parse(spacket)
#     #
#     #     return newsig
#
#     @property
#     def magic(self):
#         return "SIGNATURE"
#
#     def __init__(self):
#         super(PGPSignature, self).__init__()
#         self.signature = Signature.new()
#
#     def parse(self, data):
#         self.signature.parse(data)
#
#     def __bytes__(self):
#         return self.signature.__bytes__()
#
#     def __pgpdump__(self):
#         raise NotImplementedError()
#
#     def hashdata(self, subject):
#         # from the Computing Signatures section of RFC 4880 (http://tools.ietf.org/html/rfc4880#section-5.2.4)
#         #
#         # All signatures are formed by producing a hash over the signature
#         # data, and then using the resulting hash in the signature algorithm.
#         #
#         # For binary document signatures (type 0x00), the document data is
#         # hashed directly.  For text document signatures (type 0x01), the
#         # document is canonicalized by converting line endings to <CR><LF>,
#         # and the resulting data is hashed.
#         #
#         # ...
#         #
#         # ...
#         #
#         # ...
#         #
#         # Once the data body is hashed, then a trailer is hashed.
#         # (...) A V4 signature hashes the packet body
#         # starting from its first field, the version number, through the end
#         # of the hashed subpacket data.  Thus, the fields hashed are the
#         # signature version, the signature type, the public-key algorithm, the
#         # hash algorithm, the hashed subpacket length, and the hashed
#         # subpacket body.
#         #
#         # V4 signatures also hash in a final trailer of six octets: the
#         # version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
#         # big-endian number that is the length of the hashed data from the
#         # Signature packet (note that this number does not include these final
#         # six octets).
#         #
#         # After all this has been hashed in a single hash context, the
#         # resulting hash field is used in the signature algorithm and placed
#         # at the end of the Signature packet.
#         _data = b''
#         # h = hashlib.new(spkt.hash_algorithm.name)
#
#         # if spkt.hash_algorithm == HashAlgo.SHA1:
#         #     h = SHA.new()
#         #
#         # elif spkt.hash_algorithm == HashAlgo.SHA256:
#         #     h = SHA256.new()
#         #
#         # else:
#         #     raise NotImplementedError()
#
#         s = FileLoader(subject)
#
#         if self.signature.type == Signature.Type.BinaryDocument:
#             _data += s._bytes
#
#         else:
#             ##TODO: sign other types of things
#             raise NotImplementedError(self.sigpkt.type)  # pragma: no cover
#
#         # add the signature trailer to the hash context
#         _data += self.signature.version.__bytes__()
#         _data += self.signature.type.__bytes__()
#         _data += self.signature.key_algorithm.__bytes__()
#         _data += self.signature.hash_algorithm.__bytes__()
#         _data += self.signature.hashed_subpackets.__bytes__()
#
#         # finally, hash the final six-octet trailer and return
#         hlen = 4 + len(self.signature.hashed_subpackets.__bytes__())
#         _data += b'\x04\xff'
#         _data += int_to_bytes(hlen, 4)
#
#         return _data
#
#
# class PGPKeyBlock(PGPObject):
#     @property
#     def magic(self):
#         return self._keys[0].magic if len(self._keys) > 0 else "? KEY BLOCK"
#
#     def __init__(self):
#         super(PGPKeyBlock, self).__init__()
#         self._keys = []
#         self._userids = []
#         self._signatures = []
#
#     def parse(self, data):
#         packets = []
#
#         while data != b'':
#             packets.append(Packet.load_packet(data))
#
#             lplen = packets[-1].header.length + len(packets[-1].header.__bytes__())
#             oplen = len(packets[-1].__bytes__())
#
#             # debugging
#             if oplen != lplen:
#                 packets[-1].__bytes__()
#                 raise PGPError("__bytes__ chain {} for {}".format("incomplete" if oplen < lplen else "incorrect",
#                                                                   packets[-1].__class__))
#
#             if packets[-1].__bytes__() != data[:lplen]:
#                 packets[-1].__bytes__()
#                 raise PGPError("__bytes__ chain incorrect for {}".format(packets[-1].__class__))
#
#             data = data[len(packets[-1].__bytes__()):]
#
#         for p in packets:
#             if isinstance(p, KeyPacket):
#                 k = PGPKey()
#                 k._keypkt = p
#                 self._keys.append(k)
#
#             if isinstance(p, UserID):
#                 self._userids.append(p)
#
#             if isinstance(p, Signature):
#                 self._signatures.append(p)
#
#     def __bytes__(self):
#         raise NotImplementedError()
#
#     def __pgpdump__(self):
#         raise NotImplementedError()
#
#
# class PGPKey(PGPObject):
#     # @property
#     # def keypkts(self):
#     #     return [ packet for packet in self.packets if isinstance(packet, KeyPacket) ]
#
#     # @property
#     # def primarykey(self):
#     #     """
#     #     Reference to the primary key if this is a subkey
#     #     ?? if this is already a primary key
#     #     """
#     #     # return [ packet for packet in self.packets if type(packet) in [PubKey, PrivKey] ][0]
#     #     raise NotImplementedError()
#
#     @property
#     def primary(self):
#         """
#         True if this is a primary key
#         False if this is a subkey
#         """
#         return isinstance(self._keypkt, Primary)
#
#     @property
#     def sub(self):
#         """
#         True if this is a subkey
#         False if this is a primary key
#         """
#         return isinstance(self._keypkt, Sub)
#
#     @property
#     def public(self):
#         """
#         True if this is a public key
#         False if this is a private key
#         """
#         return isinstance(self._keypkt, Public)
#
#     @property
#     def private(self):
#         """
#         True if this is a private key
#         False if this is a public key
#         """
#         return isinstance(self._keypkt, Private)
#
#     @property
#     def magic(self):
#         return "{} KEY BLOCK".format("PRIVATE" if self.private else \
#                                      "PUBLIC" if self.public else "?")
#
#     @classmethod
#     def new(cls):
#         ##TODO: generate a new key
#         raise NotImplementedError()
#
#     def __init__(self):
#         super(PGPKey, self).__init__()
#
#         self._keypkt = None
#         self._userids = []
#         self._attrs = []
#         self._keysigs = []
#
#     def parse(self, data):
#         ##TODO: load the next key in data and return the leftovers
#         raise NotImplementedError()
#
#     def __bytes__(self):
#         raise NotImplementedError()
#
#     def __pgpdump__(self):
#         raise NotImplementedError()
#
#     def lock(self, passphrase, s2k=None):
#         """
#         Encrypt the secret key material if it is not already encrypted.
#         """
#         ##TODO: this should fail if this PGPKey is not a private key
#         ##TODO: this should fail if the secret key material is already encrypted
#         ##TODO: s2k should default to the strongest method available (which is currently Iterated)
#         raise NotImplementedError()
#
#     def unlock(self, passphrase):
#         """
#         Decrypt the secret key material if it is encrypted
#         """
#         raise NotImplementedError()
#
#     def sign(self, subject, hash=None, inline=False, sigtype=None):
#         """
#         Sign a subject with this key.
#         """
#         ##TODO: if hash is None, default to using the strongest hash in this key's preference flags
#         ##TODO: implement inline signing
#         ##TODO: implement signing things other than binary documents
#         ##TODO: sigtype should default to the binary signature type specifier rather than None
#         raise NotImplementedError()
#
#     def verify(self, subject, signature):
#         """
#         Verify a subject using this key.
#         """
#         if not isinstance(signature, PGPSignature):
#             signature = pgpload(signature)[0]
#
#         if not isinstance(signature, PGPSignature):
#             raise ValueError("signature must be a signature!")
#
#     def encrypt(self):
#         """
#         Encrypt something
#         """
#         raise NotImplementedError()
#
#     def decrypt(self):
#         """
#         Decrypt something
#         """
#         raise NotImplementedError()
