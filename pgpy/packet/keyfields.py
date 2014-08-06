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

