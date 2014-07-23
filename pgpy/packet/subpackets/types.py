""" subpacket.py
"""
import abc
import enum

from ..fields.types import PacketField
from ...util import bytes_to_int, int_to_bytes

class MetaSubPacket(abc.ABCMeta):
    __metaclass__ = abc.ABCMeta

    _registry = {}

    # @classmethod
    # def delegate(meta, cls, id):
    #     if cls.__name__ in meta.__registry:
    #         if id in meta.__registry[cls.__name__]:
    #             return meta.__registry[cls.__name__][id]
    #
    #     return False

    # def __new__(cls, name, bases, attrs):
    #     new = super(SubPacket, cls).__new__(cls, name, bases, attrs)
    #
    #     # A direct subclass of SubPacket will be a factory for its subclasses
    #     # Therefore, they are at the top level of the registry
    #     if
    @classmethod
    def __prepare__(meta, name, bases):
        # here, we'll register the root classes

        # SubPacket does not need to be registered, and should be skipped
        # otherwise, the next check breaks
        if name == "SubPacket":
            pass

        # However, direct subclasses of SubPacket are "root" nodes of the registry
        # - they are the "generic" form of each specific type of subpacket.
        elif SubPacket in bases:
            meta._registry[name] = {}

        return dict()

    def __new__(meta, name, bases, attrs):
        new = super(MetaSubPacket, meta).__new__(meta, name, bases, attrs)

        # SubPacket is the ABC, so it doesn't get registered at all
        if name == "SubPacket":
            pass

        else:
            # register to the ABC, which is SubPacket
            meta.register(SubPacket, new)

            # now, if it's not a root node of __registry, also register there
            if name not in meta._registry:
                # register subpackets of root nodes to __registry
                for base in bases:
                    if base.__name__ in meta._registry and new.id not in meta._registry[base.__name__]:
                        meta._registry[base.__name__][new.id] = new

        return new

    # def __new__(cls, packet=None):
    #     if packet is not None:
    #         new = object.__new__(OpaqueSubPacket)
    #         new.__init__()
    #         new.parse(packet)
    #
    #         ncls = MetaSubPacket.delegate(SignatureSubPacket, new.id)
    #
    #         if ncls is not None:
    #             new = object.__new__(ncls)
    #             new.__init__()
    #             new.parse(packet)
    #
    #     else:
    #         new = object.__new__(cls)
    #
    #     return new
    def __call__(cls, *args):
        def _makeobj_parse(cls, *args):
            obj = object.__new__(cls)
            obj.__init__()

            if len(args) > 0:
                obj.parse(args[0])

            return obj

        if cls.__name__ in MetaSubPacket._registry:
            obj = _makeobj_parse(MetaSubPacket._registry[cls.__name__][None], *args)

            if obj.id is not None and obj.id in MetaSubPacket._registry[cls.__name__]:
                nobj = _makeobj_parse(MetaSubPacket._registry[cls.__name__][obj.id], *args)
                del obj
                obj = nobj
                del nobj

        else:
            obj = _makeobj_parse(cls, *args)

        return obj


class SubPacket(PacketField, metaclass=MetaSubPacket):
    __metaclass__ = MetaSubPacket

    id = None

    def __init__(self):
        super(SubPacket, self).__init__()
        self.length = 0

    @abc.abstractmethod
    def parse(self, packet):
        fo = bytes_to_int(packet[:1])

        if 192 > fo:
            self.length = fo
            packet = packet[1:]

        elif 255 > fo >= 192:
            elen = bytes_to_int(packet[:2])
            self.length = ((elen - (192 << 8)) & 0xFF00) + ((elen & 0xFF) + 192)
            packet = packet[2:]

        else:
            self.length = bytes_to_int(packet[1:5])
            packet = packet[5:]

        if self.id is None:
            self.id = bytes_to_int(packet[:1])

        return packet[1:]

    @abc.abstractmethod
    def __bytes__(self):
        _bytes = b''
        # 1 octet length
        if self.length < 192:
            _bytes += int_to_bytes(self.length)

        # 2 octet length
        elif self.length < 8384:
            _bytes += int_to_bytes(((self.length & 0xFF00) + (192 << 8)) + ((self.length & 0xFF) - 192), 2)

        # 5 octet length
        else:
            _bytes += b'\xFF' + int_to_bytes(self.length, 4)

        _bytes += int_to_bytes(self.id) if self.id is not None else b'\x00'

        return _bytes


class FlagEnum(enum.IntEnum):
    ##TODO: implement this
    ##      look at http://blog.jameskyle.org/2010/09/enum-masks-idiom-in-python
    ##      for possible ideas
    pass