""" types.py
"""
# for Python 2.7
from __future__ import division

import abc
import base64
import binascii
import collections
import os
import re

from enum import EnumMeta
from enum import IntEnum

import requests

from ._author import __version__

from .decorators import TypedProperty

from .util import is_ascii
from .util import is_path

try:  # pragma: no cover
    e = FileNotFoundError
except NameError:  # pragma: no cover
    e = IOError


class PGPDump(object):
    def __init__(self, obj):
        if not isinstance(obj, PGPObject):
            raise ValueError("Expected: A PGPObject")

        self._pgpobj = obj

    def __str__(self):
        return str(self._pgpobj)


class FileLoader(object):

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, ppath):
        if not (is_path(ppath)):
            raise ValueError("Expected: valid path")

        self._path = ppath

    @classmethod
    def load(cls, lf):
        _bytes = b''

        # None means nothing to load
        if lf is None:
            pass

        # This is a file-like object
        elif hasattr(lf, "read"):
            _bytes = bytes(lf.read())

        # this could be a path
        elif is_path(lf) and ('/' in lf or '\\' in lf):
            # this is a URI
            if "://" in lf:
                r = requests.get(lf, verify=True)

                if not r.ok:
                    raise e(lf)

                _bytes = r.content

            # this is an existing file
            elif os.path.isfile(lf):
                with open(lf, 'rb') as lf:
                    _bytes = bytes(lf.read())

            # this is a new file
            elif os.path.isdir(os.path.dirname(lf)):
                pass

            # this is all wrong
            else:
                raise e(lf)

        # this is probably data we want to load directly
        elif type(lf) in [str, bytes]:
            _bytes = bytes(lf)

        # something else entirely
        else:
            raise TypeError(type(lf))

        return _bytes

    def __init__(self):
        self._path = ''

    def write(self, binary=False):
        """
        Writes the contents to disk, at the path specified in :py:attr:`path`
        :param bool binary=False:
            if True, writes __bytes__ in binary mode
            if False, writes __str__ in ASCII
        """
        if self.path is None:
            raise e("path needs to be set before calling .write")

        with open(self.path, 'wb' if binary else 'w') as fp:
            fp.write(self.__bytes__() if binary else str(self))


class Exportable(FileLoader, metaclass=abc.ABCMeta):
    __metaclass__ = abc.ABCMeta

    __crc24_init = 0x0B074CE
    __crc24_poly = 0x1864CFB

    __armor_fmt = '-----BEGIN PGP {block_type}-----\n' \
                  '{headers}\n' \
                  '{packet}\n' \
                  '={crc}\n' \
                  '-----END PGP {block_type}-----\n'

    @abc.abstractproperty
    def magic(self):
        """The magic string identifier for the current PGP type"""
        return ""

    def __init__(self):
        super(Exportable, self).__init__()
        self.ascii_headers = collections.OrderedDict()
        self.ascii_headers['Version'] = 'PGPy v' + __version__ # Default value

    @abc.abstractmethod
    def __bytes__(self):
        return b''

    def __str__(self):
        payload = base64.b64encode(self.__bytes__()).decode()
        payload = '\n'.join([ payload[i:(i + 64)] for i in range(0, len(payload), 64) ])

        return self.__armor_fmt.format(
            block_type=self.magic,
            headers=''.join([ '{key}: {val}\n'.format(key=key, val=val) for key, val in self.ascii_headers.items() ]),
            packet=payload,
            crc=base64.b64encode(Header.int_to_bytes(self.crc24(), 3)).decode()
        )

    @staticmethod
    def ascii_unarmor(text):
        """
        Takes an ASCII-armored PGP block and returns the decoded byte value.

        :param text:
        :return:
        :raises:
        """
        if not is_ascii(text):
            raise TypeError("Expected: ASCII")

        if isinstance(text, (bytes, bytearray)):
            text = text.decode()

        # the re.VERBOSE flag allows for:
        #  - whitespace is ignored except when in a character class or escaped
        #  - anything after a '#' that is not escaped or in a character class is ignored, allowing for comments
        m = re.match(r"""# armor header line; capture the variable part of the magic text
                         ^-{5}BEGIN\ PGP\ (?P<magic>[A-Z0-9 ,]+)-{5}$\n
                         # try to capture all the headers into one capture group
                         # if this doesn't match, m['headers'] will be None
                         ((?P<headers>(^.+:\ .+$\n)+))?(\n)?
                         # capture all lines of the body, up to 76 characters long,
                         # including the newline, and the pad character(s)
                         (?P<body>([A-Za-z0-9+/]{1,75}={,2}\n)+)
                         # capture the armored CRC24 value
                         ^=(?P<crc>[A-Za-z0-9+/]{4})$\n
                         # finally, capture the armor tail line, which must match the armor header line
                         ^-{5}END\ PGP\ (?P=magic)-{5}$\n
                         """,
                     text, flags=re.MULTILINE | re.VERBOSE)

        if m is None:
            raise ValueError("Expected: ASCII-armored PGP data")

        m = m.groupdict()

        if m['headers'] is not None:
            m['headers'] = collections.OrderedDict(re.findall('^(?P<key>.+): (?P<value>.+)$\n?', m['headers'], flags=re.MULTILINE))

        if m['body'] is not None:
            m['body'] = bytearray(base64.b64decode(m['body'].encode()))

        if m['crc'] is not None:
            m['crc'] = Header.bytes_to_int(base64.b64decode(m['crc'].encode()))

        return m

    def crc24(self, data=None):
        # CRC24 computation, as described in the RFC 4880 section on Radix-64 Conversions
        #
        # The checksum is a 24-bit Cyclic Redundancy Check (CRC) converted to
        # four characters of radix-64 encoding by the same MIME base64
        # transformation, preceded by an equal sign (=).  The CRC is computed
        # by using the generator 0x864CFB and an initialization of 0xB704CE.
        # The accumulation is done on the data before it is converted to
        # radix-64, rather than on the converted data.

        if data is None:
            data = self.__bytes__()

        crc = self.__crc24_init
        sig = [ ord(i) for i in data ] if type(data) is str else data

        for loc in range(0, len(data)):
            crc ^= sig[loc] << 16

            for i in range(0, 8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= self.__crc24_poly

        return crc & 0xFFFFFF


class PGPObject(object, metaclass=abc.ABCMeta):
    __metaclass__ = abc.ABCMeta

    @staticmethod
    def bytes_to_int(b, order='big'):
        """convert bytes to integer"""
        if hasattr(int, 'from_bytes'):
            return int.from_bytes(b, order)
        else:
            # fall back to the old method
            return int(binascii.hexlify(b), 16)

    @staticmethod
    def int_to_bytes(i, minlen=1, order='big'):
        """convert integer to bytes"""
        if hasattr(int, 'to_bytes'):
            return i.to_bytes(minlen, order)
        else:
            # fall back to the old method
            plen = max(int((i.bit_length() + 7) // 8) * 2, (minlen * 2))
            hexstr = '{0:0{1}x}'.format(i, plen).encode()
            return binascii.unhexlify(hexstr)

    @abc.abstractmethod
    def parse(self, packet):
        raise NotImplementedError()

    @abc.abstractmethod
    def __pgpdump__(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def __bytes__(self):
        raise NotImplementedError()


class Field(PGPObject):
    __slots__ = []

    @abc.abstractmethod
    def __len__(self):
        return 0


class Header(Field):
    __slots__ = ['_len', '_lenfmt', '_llen']

    @staticmethod
    def encode_length(l, nhf=True, llen=1):
        def _new_length(l):
            if 192 > l:
                return Header.int_to_bytes(l)

            elif 8384 > l:
                elen = ((l & 0xFF00) + (192 << 8)) + ((l & 0xFF) - 192)
                return Header.int_to_bytes(elen, 2)

            return b'\xFF' + Header.int_to_bytes(l, 4)


        def _old_length(l, llen):
            return Header.int_to_bytes(l, llen) if llen > 0 else b''

        return _new_length(l) if nhf else _old_length(l, llen)

    @TypedProperty
    def length(self):
        return self._len
    @length.int
    def length(self, val):
        self._len = val
    @length.bytearray
    @length.bytes
    def length(self, val):
        def _new_len(b):
            fo = b[0]

            if 192 > fo:
                self._len = self.bytes_to_int(b[:1])

            elif 224 > fo:  # >= 192 is implied
                dlen = self.bytes_to_int(b[:2])
                self._len = ((dlen - (192 << 8)) & 0xFF00) + ((dlen & 0xFF) + 192)

            elif 255 == fo:
                self._len = self.bytes_to_int(b[1:5])

            else:
                raise ValueError("Malformed length!")

        def _old_len(b):
            if self.llen > 0:
                self._len = self.bytes_to_int(b[:self.llen])

            else:
                self._len = 0

        _new_len(val) if self._lenfmt == 1 else _old_len(val)

    @TypedProperty
    def llen(self):
        l = self.length
        lf = self._lenfmt

        if lf == 1:
            # new-format length
            if 192 > l:
                return 1

            elif 8384 > self.length:  # >= 192 is implied
                return 2

            else:
                return 5

        else:
            # old-format length
            ##TODO: what if _llen needs to be (re)computed?
            return self._llen
    @llen.int
    def llen(self, val):
        if self._lenfmt == 0:
            self._llen = {0: 1, 1: 2, 2: 4, 3: 0}[val]

    def __init__(self):
        self._len = 1
        self._llen = 1
        self._lenfmt = 1


class MetaDispatchable(abc.ABCMeta):
    """
    MetaDispatchable is a metaclass for objects that subclass Dispatchable
    """


    _registry = {}
    """
    _registry is the Dispatchable class registry. It uses the following format:

    { RootClass: RootClass }:
        denotes a root class for a set of Dispatchable objects.
        This is so "if RootClassName in MetaDispatchable._registry" works

        A RootClass is successfully registered as such provided the following conditions are met:
         - it inherits (directly or indirectly) from Dispatchable
         - __typeid__ is -1

    { (RootClass, None): OpaqueClass }:
        denotes the default ("opaque") for a given RootClass.

        An OpaqueClass is successfully registered as such provided the following conditions are met:
         - it inherits directly from a RootClass
         - __typeid__ is None

    { (RootClass, TypeID): SubClass }:
        denotes the class that handles the type given in TypeID

        a SubClass is successfully registered as such provided the following conditions are met:
         - it inherits (directly or indirectly) from a RootClass
         - __typeid__ is a positive int
         - the given typeid is not already registered
    """

    def __new__(mcls, name, bases, attrs):
        ncls = super(MetaDispatchable, mcls).__new__(mcls, name, bases, attrs)

        if '__typeid__' in attrs and (not hasattr(ncls.__typeid__, '__isabstractmethod__')):
            # this is a root class
            if ncls.__typeid__ == -1:
                MetaDispatchable._registry[ncls] = ncls

            # this is likely a dispatch target class
            else:
                ##TODO: need to register classes to their ABC, if possible

                rcl = [ rc for rc in MetaDispatchable._registry
                        if (not isinstance(rc, tuple))
                        and issubclass(ncls, rc) ]

                for rc in rcl:
                    MetaDispatchable._registry[(rc, ncls.__typeid__)] = ncls

        # finally, return the new class object
        return ncls

    def __call__(cls, *args):
        def _makeobj(cls):
            obj = object.__new__(cls)
            obj.__init__()
            return obj

        rcl = [ rc for rc in MetaDispatchable._registry
                if (not isinstance(rc, tuple))
                and issubclass(cls, rc) ]

        if len(rcl) > 0 and len(args) > 0:
            header = rcl[0].__headercls__()
            header.parse(args[0])

            if (rcl[0], header.typeid) in MetaDispatchable._registry:
                obj = _makeobj(MetaDispatchable._registry[(rcl[0], header.typeid)])

            else:
                obj = _makeobj(MetaDispatchable._registry[(rcl[0], None)])

            obj.header = header
            obj.parse(args[0])

        else:
            obj = _makeobj(cls)

            ##TODO: this whole method does not work here
            ##      assigning memory after _makeobj means __init__ has already run and probably failed
            ##      also, since these objects are not really meant to be instantiated on their own, it doesn't make sense
            ##      to allocate memory for them like that
            # if len(args) == 0:
            #     b = bytearray(b'\x01\x00')
            #     obj.header._bytes = lambda: memoryview(b).__enter__()
            #     obj._bytes = lambda: memoryview().__enter__()[obj._offset:(obj._offset + obj.header._llen + obj.header.length)]

        return obj


class Dispatchable(PGPObject, metaclass=MetaDispatchable):
    __metaclass__ = MetaDispatchable

    @abc.abstractproperty
    def __typeid__(self):
        return False


class SignatureVerification(object):
    """
    Returned by :py:meth:`pgpy.PGPKeyring.verify`

    Can be compared directly as a boolean to determine whether or not the specified signature verified.
    """
    def __init__(self):
        self._verified = False

        self.signature = None
        """
        The :py:class:`~pgpy.pgp.PGPSignature` that was used in the verification that returned this
        """
        self.key = None
        """
        The key (if available) that was used to verify the signature
        """
        self.subject = None
        """
        The subject of the verification
        """

    # Python 2
    def __nonzero__(self):
        return self._verified  # pragma: no cover

    # Python 3
    def __bool__(self):
        return self._verified  # pragma: no cover

    def __repr__(self):  # pragma: no cover
        return "SignatureVerification({key}, {verified})".format(verified=str(bool(self)), key=self.key.keyid)


class FlagEnumMeta(EnumMeta):
    def __and__(self, other):
        return set([f for f in self._member_map_.values() if f.value & other])

    def __rand__(self, other):
        return set([f for f in self._member_map_.values() if f.value & other])


class FlagEnum(IntEnum, metaclass=FlagEnumMeta):
    pass


class Fingerprint(str):
    @property
    def keyid(self):
        return str(self).replace(' ', '')[-16:]

    @property
    def shortid(self):
        return str(self).replace(' ', '')[-8:]

    def __new__(cls, content):
        # validate input before continuing: this should be a string of 40 hex digits
        content = content.upper().replace(' ', '')
        if not bool(re.match(r'^[A-Z0-9]{40}$', content)):
            raise ValueError("Expected: String of 40 hex digits")

        # store in the format: "AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"
        #                                               ^^ note 2 spaces here
        content = ''.join([ j for i in zip([ content[x:(x + 4)] for x in range(0, 40, 4) ],
                                           [' '] * 4 + ['  '] + [' '] * 5) for j in i ][:-1])
        return str.__new__(cls, content)

    def __eq__(self, other):
        if isinstance(other, Fingerprint):
            return self == other

        if isinstance(other, (str, bytes, bytearray)):
            other = str(other).replace(' ', '')
            return any([self.replace(' ', '') == other,
                        self.keyid == other,
                        self.shortid == other])

        return False

    def __hash__(self):
        return hash(str(self))

    def __int__(self):
        return int(self.replace(' ', ''), 16)