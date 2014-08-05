""" keyfields.py
"""
# class MPIFields(object):
#     field = {'bitlen': 0, 'bytes': b''}
#     sigfields = []
#     pubfields = []
#     privfields = []
#
#     @property
#     def privempty(self):
#         return not any([ getattr(self, f)['bitlen'] > 0 for f in self.privfields ])
#
#     def __init__(self):
#         self.fields = collections.OrderedDict()
#
#     def parse(self, packet, pkt, sec=False):
#         ##TODO: change this to work more like like subpackets
#         # determine fields
#         if pkt.key_algorithm == PubKeyAlgo.RSAEncryptOrSign:
#             self.__class__ = RSAMPI
#
#         if pkt.key_algorithm == PubKeyAlgo.DSA:
#             self.__class__ = DSAMPI
#
#         if pkt.key_algorithm == PubKeyAlgo.ElGamal:
#             self.__class__ = ElGMPI
#
#         if self.__class__ == MPIFields:
#             raise NotImplementedError(pkt.key_algorithm)
#
#         # determine how many fields we need to parse
#         fields = []
#
#         from ..packets import Signature
#         if isinstance(pkt, Signature):
#             fields = self.sigfields
#
#         from ..packets import KeyPacket
#         from ..packets import Private
#         if isinstance(pkt, KeyPacket) and not sec:
#             fields = self.pubfields
#
#         if isinstance(pkt, Private) and sec:
#             fields = self.privfields
#
#         # if fields is 0, we got something wrong, or this type isn't taken into account yet
#         if len(fields) == 0:
#             raise NotImplementedError(pkt.__class__)
#
#         # now parse!
#         # pos = 0
#         for field in fields:
#             bitlen = bytes_to_int(packet[:2])
#             packet = packet[2:]
#
#             bytelen = (bitlen + 7) // 8
#
#             getattr(self, field)['bitlen'] = bitlen
#             getattr(self, field)['bytes'] = packet[:bytelen]
#             packet = packet[bytelen:]
#
#         return packet
#
#     def sigbytes(self):
#         _bytes = b''
#         for field in [ getattr(self, vf) for vf in self.sigfields ]:
#             _bytes += int_to_bytes(field['bitlen'], 2)
#             _bytes += field['bytes']
#
#         return _bytes
#
#     def pubbytes(self):
#         _bytes = b''
#         for field in [ getattr(self, vf) for vf in self.pubfields ]:
#             _bytes += int_to_bytes(field['bitlen'], 2)
#             _bytes += field['bytes']
#
#         return _bytes
#
#     def privbytes(self):
#         _bytes = b''
#         for field in [ getattr(self, vf) for vf in self.privfields ]:
#             _bytes += int_to_bytes(field['bitlen'], 2)
#             _bytes += field['bytes']
#
#         return _bytes
#
#     def reset(self):
#         for k in [ k for k in self.privfields if self.fields[k]['bitlen'] > 0 ]:
#             delattr(self, k)
#
#
# def propinator(field, name, fdel=False):
#     # some metaprogramming going on here - this is a generic property getter
#     # that will be assigned to several when MPIFields morphs into one of its subclasses
#     def field_get(self, name):
#         if name not in self.fields.keys():
#             self.fields[name] = self.field.copy()
#
#         return self.fields[name]
#
#     # and this is a generic property setter that will also be assigned
#     def field_set(self, name, value):
#         self.fields[name] = value
#
#     # and this is a generic property deleter for private key values
#     def field_del(self, name):
#         self.fields[name]['bitlen'] = 0
#
#         bufsize = len(self.fields[name]['bytes'])
#         offset = sys.getsizeof(self.fields[name]['bytes']) - (bufsize + 1)
#         ctypes.memset(id(self.fields[name]['bytes']) + offset, 0, bufsize)
#
#     return property(
#         functools.partial(field_get, name=field),
#         functools.partial(field_set, name=field),
#         functools.partial(field_del, name=field) if fdel else None,
#         name
#     )
#
#
# class RSAMPI(MPIFields):
#     encoding = 'PKCS-1'
#     sigfields = ['md_mod_n']
#     pubfields = ['n', 'e']
#     privfields = ['d', 'p', 'q', 'u']
#
#     # signature fields
#     md_mod_n = propinator('md_mod_n', 'RSA m^d mod n')
#
#     # public key fields
#     n = propinator('n', 'RSA n')
#     e = propinator('e', 'RSA e')
#
#     # private key fields
#     d = propinator('d', 'RSA d', fdel=True)
#     p = propinator('p', 'RSA p', fdel=True)
#     q = propinator('q', 'RSA q', fdel=True)
#     u = propinator('u', 'RSA u', fdel=True)
#
#
# class DSAMPI(MPIFields):
#     encoding = 'hash(DSA q bits)'
#     sigfields = ['r', 's']
#     pubfields = ['p', 'q', 'g', 'y']
#     privfields = ['x']
#
#     # signature fields
#     r = propinator('r', 'DSA r')
#     s = propinator('s', 'DSA s')
#
#     # public key fields
#     p = propinator('p', 'DSA p')
#     q = propinator('q', 'DSA q')
#     g = propinator('g', 'DSA g')
#     y = propinator('y', 'DSA y')
#
#     # private key fields
#     x = propinator('x', 'DSA x', fdel=True)
#
#     @property
#     def as_asn1_der(self):
#         # turn filled in values in self.fields into an ASN.1 sequence of integers
#         # (see http://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One#Example_encoded_in_DER)
#         # type tag indicating that this is a SEQUENCE
#         _bytes = b'\x30'
#         # next is the constructed length of all integer fields, so construct those first
#         _fbytes = b''
#         for item in [ f['bytes'] for f in self.fields.values() if f['bitlen'] > 0 ]:
#             # field type is INTEGER, so this is 0x02
#             _fbytes += b'\x02'
#
#             # length in octets of this field
#             if len(item) > 128:
#                 # long form
#                 _fbytes += int_to_bytes(128 ^ len(int_to_bytes(len(item))))
#             _fbytes += int_to_bytes(len(item))
#
#             # and the field itself
#             _fbytes += item
#
#         # now add the length of _fbytes to _bytes
#         if len(_fbytes) > 128:
#             # long form
#             _bytes += int_to_bytes(128 ^ len(int_to_bytes(len(_fbytes))))
#         _bytes += int_to_bytes(len(_fbytes))
#
#         # and finally _fbytes
#         _bytes += _fbytes
#
#         return _bytes
#
#
# class ElGMPI(MPIFields):
#     # ElGamal can't sign, so no signature fields
#     sigfields = []
#     pubfields = ['p', 'g', 'y']
#     privfields = ['x']
#
#     # public key fields
#     p = propinator('p', 'ElGamal p')
#     g = propinator('g', 'ElGamal g')
#     y = propinator('y', 'ElGamal y')
#
#     # private key fields
#     x = propinator('x', 'ElGamal x', fdel=True)
#
#
# class String2Key(PacketField):
#     class Type(PFIntEnum):
#         Simple = 0
#         Salted = 1
#         Iterated = 3
#
#         def __str__(self):
#             if self == String2Key.Type.Simple:
#                 return "Simple string-to-key"
#
#             if self == String2Key.Type.Salted:
#                 return "Salted string-to-key"
#
#             if self == String2Key.Type.Iterated:
#                 return "Iterated and salted string-to-key"
#
#             raise NotImplementedError(self.name)  # pragma: no cover
#
#     def __init__(self):
#         super(String2Key, self).__init__()
#         self.id = 0
#         self.alg = SymmetricKeyAlgo.Plaintext
#         self.type = String2Key.Type.Simple
#         self.hash = HashAlgo.Invalid
#         self.salt = None
#         self.c = None
#         self.count = None
#         self.iv = b''
#
#     def parse(self, packet):
#         self.id = bytes_to_int(packet[:1])
#         packet = packet[1:]
#
#         if self.id in [254, 255]:
#             self.alg = SymmetricKeyAlgo(bytes_to_int(packet[:1]))
#             packet = packet[1:]
#
#             self.type = String2Key.Type(bytes_to_int(packet[:1]))
#             packet = packet[1:]
#
#             self.hash = HashAlgo(bytes_to_int(packet[:1]))
#             packet = packet[1:]
#
#             if self.type in [String2Key.Type.Salted, String2Key.Type.Iterated]:
#                 self.salt = packet[:8]
#                 packet = packet[8:]
#
#             if self.type == String2Key.Type.Iterated:
#                 self.c = bytes_to_int(packet[:1])
#                 packet = packet[1:]
#
#                 self.count = (16 + (self.c & 15)) << ((self.c >> 4) + 6)
#
#         if self.id != 0:
#             self.iv = packet[:(self.alg.block_size // 8)]
#             packet = packet[(self.alg.block_size // 8):]
#
#         return packet
#
#     def derive_key(self, passphrase):
#         # we use the fields stored here along with the RFC 4880 String-to-Key usage description
#         # to derive a symmetric key from the given passphrase.
#
#         # how long does our key need to be, and how many hash contexts do we need?
#         keylen = self.alg.keylen
#         hashlen = self.hash.digestlen
#         ctx = int(math.ceil(keylen / float(hashlen)))
#
#         h = []
#         # instantiate our hash context(s)
#         for i in range(0, ctx):
#             h.append(hashlib.new(self.hash.name, b'\x00' * i))
#
#         # Simple S2K
#         hsalt = b''
#         hpass = passphrase.encode()
#
#         # Salted S2K (or Iterated)
#         if self.type in [String2Key.Type.Salted, String2Key.Type.Iterated]:
#             hsalt = self.salt
#
#         # Set the total to-be-hashed octet count
#         count = len(hsalt + hpass)
#         if self.type == String2Key.Type.Iterated and self.count > len(hsalt + hpass):
#             count = self.count
#
#         while count > len(hsalt + hpass):
#             for hc in h:
#                 hc.update(hsalt)
#                 hc.update(hpass)
#             count -= len(hsalt + hpass)
#
#         if count > 0:
#             for hc in h:
#                 hc.update((hsalt + hpass)[:count])
#
#         # and finally, return!
#         return b''.join([hc.digest() for hc in h])[:int(keylen / 8)]
#
#     def __bytes__(self):
#         _bytes = b''
#         _bytes += int_to_bytes(self.id)
#
#         if self.id in [254, 255]:
#             _bytes += int_to_bytes(self.alg.value)
#             _bytes += int_to_bytes(self.type.value)
#             _bytes += int_to_bytes(self.hash.value)
#
#             if self.type in [String2Key.Type.Salted, String2Key.Type.Iterated]:
#                 _bytes += self.salt
#
#             if self.type == String2Key.Type.Iterated:
#                 _bytes += int_to_bytes(self.c)
#
#         if self.id != 0:
#             _bytes += self.iv
#
#         return _bytes
