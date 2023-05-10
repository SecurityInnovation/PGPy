""" types.py
"""

import abc
import base64
import binascii
import bisect
import codecs
import collections
import operator
import os
import re
import warnings
import weakref

from enum import IntEnum

from typing import Optional, Dict, List, Set, Tuple, Type, Union, OrderedDict, TypeVar, Generic

from .decorators import sdproperty

from .errors import PGPError

__all__ = ['Armorable',
           'ParentRef',
           'PGPObject',
           'Field',
           'Fingerprint',
           'FingerprintDict',
           'FingerprintValue',
           'Header',
           'KeyID',
           'MetaDispatchable',
           'Dispatchable',
           'DispatchGuidance',
           'SignatureVerification',
           'SorteDeque']


class Armorable(metaclass=abc.ABCMeta):
    __crc24_init = 0x0B704CE
    __crc24_poly = 0x1864CFB

    __armor_fmt = '-----BEGIN PGP {block_type}-----\n' \
                  '{headers}\n' \
                  '{packet}\n' \
                  '={crc}\n' \
                  '-----END PGP {block_type}-----\n'

    # the re.VERBOSE flag allows for:
    #  - whitespace is ignored except when in a character class or escaped
    #  - anything after a '#' that is not escaped or in a character class is ignored, allowing for comments
    __armor_regex = re.compile(r"""# This capture group is optional because it will only be present in signed cleartext messages
                         (^-{5}BEGIN\ PGP\ SIGNED\ MESSAGE-{5}(?:\r?\n)
                          (Hash:\ (?P<hashes>[A-Za-z0-9\-,]+)(?:\r?\n){2})?
                          (?P<cleartext>(.*\r?\n)*(.*(?=\r?\n-{5})))(?:\r?\n)
                         )?
                         # armor header line; capture the variable part of the magic text
                         ^-{5}BEGIN\ PGP\ (?P<magic>[A-Z0-9 ,]+)-{5}(?:\r?\n)
                         # try to capture all the headers into one capture group
                         # if this doesn't match, m['headers'] will be None
                         (?P<headers>(^.+:\ .+(?:\r?\n))+)?(?:\r?\n)?
                         # capture all lines of the body, up to 76 characters long,
                         # including the newline, and the pad character(s)
                         (?P<body>([A-Za-z0-9+/]{1,76}={,2}(?:\r?\n))+)
                         # capture the armored CRC24 value
                         ^=(?P<crc>[A-Za-z0-9+/]{4})(?:\r?\n)
                         # finally, capture the armor tail line, which must match the armor header line
                         ^-{5}END\ PGP\ (?P=magic)-{5}(?:\r?\n)?
                         """, flags=re.MULTILINE | re.VERBOSE)

    @property
    def charset(self) -> str:
        return self.ascii_headers.get('Charset', 'utf-8')

    @charset.setter
    def charset(self, encoding: str) -> None:
        self.ascii_headers['Charset'] = codecs.lookup(encoding).name

    @staticmethod
    def is_utf8(text: Union[str, bytes, bytearray]) -> bool:
        if isinstance(text, str):
            return True
        else:
            try:
                text.decode('utf-8')
                return True
            except UnicodeDecodeError:
                return False

    @staticmethod
    def is_ascii(text: Union[str, bytes, bytearray]) -> bool:
        '''This is a deprecated, pointless method'''
        if isinstance(text, str):
            return bool(re.match(r'^[ -~\r\n\t]*$', text, flags=re.ASCII))

        if isinstance(text, (bytes, bytearray)):
            return bool(re.match(br'^[ -~\r\n\t]*$', text, flags=re.ASCII))

        raise TypeError("Expected: ASCII input of type str, bytes, or bytearray")  # pragma: no cover

    @staticmethod
    def is_armor(text: Union[str, bytes, bytearray]) -> bool:
        """
        Whether the ``text`` provided is an ASCII-armored PGP block.
        :param text: A possible ASCII-armored PGP block.
        :raises: :py:exc:`TypeError` if ``text`` is not a ``str``, ``bytes``, or ``bytearray``
        :returns: Whether the text is ASCII-armored.
        """
        if isinstance(text, (bytes, bytearray)):  # pragma: no cover
            try:
                text = text.decode('utf-8')
            except UnicodeDecodeError:
                return False

        return Armorable.__armor_regex.search(text) is not None

    @staticmethod
    def ascii_unarmor(text: Union[str, bytes, bytearray]) -> Dict[str, Optional[Union[str, bytes, bytearray, List[str]]]]:
        """
        Takes an ASCII-armored PGP block and returns the decoded byte value.

        :param text: An ASCII-armored PGP block, to un-armor.
        :raises: :py:exc:`ValueError` if ``text`` did not contain an ASCII-armored PGP block.
        :raises: :py:exc:`TypeError` if ``text`` is not a ``str``, ``bytes``, or ``bytearray``
        :returns: A ``dict`` containing information from ``text``, including the de-armored data.
        It can contain the following keys: ``magic``, ``headers``, ``hashes``, ``cleartext``, ``body``, ``crc``.
        """
        if not isinstance(text, str) and not Armorable.is_utf8(text):
            return {'magic': None, 'headers': None, 'body': bytearray(text), 'crc': None}

        if isinstance(text, (bytes, bytearray)):  # pragma: no cover
            text = text.decode('latin-1')

        matcher = Armorable.__armor_regex.search(text)

        if matcher is None:  # pragma: no cover
            raise ValueError("Expected: ASCII-armored PGP data")

        m = matcher.groupdict()

        if m['hashes'] is not None:
            m['hashes'] = m['hashes'].split(',')

        if m['headers'] is not None:
            m['headers'] = collections.OrderedDict(re.findall('^(?P<key>.+): (?P<value>.+)$\n?', m['headers'], flags=re.MULTILINE))

        if m['body'] is not None:
            try:
                m['body'] = bytearray(base64.b64decode(m['body'].encode()))

            except (binascii.Error, TypeError) as ex:
                raise PGPError(str(ex)) from ex

        if m['crc'] is not None:
            m['crc'] = Header.bytes_to_int(base64.b64decode(m['crc'].encode()))
            if Armorable.crc24(m['body']) != m['crc']:
                warnings.warn('Incorrect crc24', stacklevel=3)

        return m

    @staticmethod
    def crc24(data):
        # CRC24 computation, as described in the RFC 4880 section on Radix-64 Conversions
        #
        # The checksum is a 24-bit Cyclic Redundancy Check (CRC) converted to
        # four characters of radix-64 encoding by the same MIME base64
        # transformation, preceded by an equal sign (=).  The CRC is computed
        # by using the generator 0x864CFB and an initialization of 0xB704CE.
        # The accumulation is done on the data before it is converted to
        # radix-64, rather than on the converted data.
        crc = Armorable.__crc24_init

        if not isinstance(data, bytearray):
            data = iter(data)

        for b in data:
            crc ^= b << 16

            for i in range(8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= Armorable.__crc24_poly

        return crc & 0xFFFFFF

    @abc.abstractproperty
    def magic(self):
        """The magic string identifier for the current PGP type"""

    @classmethod
    def from_file(cls, filename):
        with open(filename, 'rb') as file:
            obj = cls()
            data = bytearray(os.path.getsize(filename))
            file.readinto(data)

        po = obj.parse(data)

        if po is not None:
            return (obj, po)

        return obj  # pragma: no cover

    @classmethod
    def from_blob(cls, blob):
        obj = cls()
        if (not isinstance(blob, bytes)) and (not isinstance(blob, bytearray)):
            po = obj.parse(bytearray(blob, 'latin-1'))

        else:
            po = obj.parse(bytearray(blob))

        if po is not None:
            return (obj, po)

        return obj  # pragma: no cover

    def __init__(self):
        super().__init__()
        self.ascii_headers = collections.OrderedDict()

    def __str__(self):
        payload = base64.b64encode(self.__bytes__()).decode('latin-1')
        payload = '\n'.join(payload[i:(i + 64)] for i in range(0, len(payload), 64))

        return self.__armor_fmt.format(
            block_type=self.magic,
            headers=''.join('{key}: {val}\n'.format(key=key, val=val) for key, val in self.ascii_headers.items()),
            packet=payload,
            crc=base64.b64encode(PGPObject.int_to_bytes(self.crc24(self.__bytes__()), 3)).decode('latin-1')
        )

    def __copy__(self):
        obj = self.__class__()
        obj.ascii_headers = self.ascii_headers.copy()

        return obj


class ParentRef:
    # mixin class to handle weak-referencing a parent object
    @property
    def _parent(self):
        if isinstance(self.__parent, weakref.ref):
            return self.__parent()
        return self.__parent

    @_parent.setter
    def _parent(self, parent):
        try:
            self.__parent = weakref.ref(parent)

        except TypeError:
            self.__parent = parent

    @property
    def parent(self):
        return self._parent

    def __init__(self):
        super().__init__()
        self._parent = None


class PGPObject(metaclass=abc.ABCMeta):

    @staticmethod
    def int_byte_len(i):
        return (i.bit_length() + 7) // 8

    @staticmethod
    def bytes_to_int(b, order='big'):  # pragma: no cover
        """convert bytes to integer"""

        return int.from_bytes(b, order)

    @staticmethod
    def int_to_bytes(i, minlen=1, order='big'):  # pragma: no cover
        """convert integer to bytes"""
        blen = max(minlen, PGPObject.int_byte_len(i), 1)

        return i.to_bytes(blen, order)

    @staticmethod
    def text_to_bytes(text):
        if text is None:
            return text

        # if we got bytes, just return it
        if isinstance(text, (bytearray, bytes)):
            return text

        # if we were given a unicode string, or if we translated the string into utf-8,
        # we know that Python already has it in utf-8 encoding, so we can now just encode it to bytes
        return text.encode('utf-8')

    @staticmethod
    def bytes_to_text(text):
        if text is None or isinstance(text, str):
            return text

        return text.decode('utf-8')

    @abc.abstractmethod
    def parse(self, packet):
        """this method is too abstract to understand"""

    @abc.abstractmethod
    def __bytearray__(self):
        """
        Returns the contents of concrete subclasses in a binary format that can be understood by other OpenPGP
        implementations
        """

    def __bytes__(self):
        """
        Return the contents of concrete subclasses in a binary format that can be understood by other OpenPGP
        implementations
        """
        # this is what all subclasses will do anyway, so doing this here we can reduce code duplication significantly
        return bytes(self.__bytearray__())


class Field(PGPObject):
    @abc.abstractmethod
    def __len__(self):
        """Return the length of the output of __bytes__"""


class Header(Field):
    @staticmethod
    def encode_length(length, nhf=True, llen=1):
        def _new_length(nl):
            if 192 > nl:
                return Header.int_to_bytes(nl)

            elif 8384 > nl:
                elen = ((nl & 0xFF00) + (192 << 8)) + ((nl & 0xFF) - 192)
                return Header.int_to_bytes(elen, 2)

            return b'\xFF' + Header.int_to_bytes(nl, 4)

        def _old_length(nl, llen):
            return Header.int_to_bytes(nl, llen) if llen > 0 else b''

        return _new_length(length) if nhf else _old_length(length, llen)

    @sdproperty
    def length(self):
        return self._len

    @length.register(int)
    def length_int(self, val):
        self._len = val

    @length.register(bytes)
    @length.register(bytearray)
    def length_bin(self, val):
        def _new_len(b):
            def _parse_len(a, offset=0):
                # returns (the parsed length, size of length field, whether the length was of partial type)
                fo = a[offset]

                if 192 > fo:
                    return (self.bytes_to_int(a[offset:offset + 1]), 1, False)

                elif 224 > fo:  # >= 192 is implied
                    dlen = self.bytes_to_int(b[offset:offset + 2])
                    return (((dlen - (192 << 8)) & 0xFF00) + ((dlen & 0xFF) + 192), 2, False)

                elif 255 > fo:  # >= 224 is implied
                    # this is a partial-length header
                    return (1 << (fo & 0x1f), 1, True)

                elif 255 == fo:
                    return (self.bytes_to_int(b[offset + 1:offset + 5]), 5, False)

                else:  # pragma: no cover
                    raise ValueError("Malformed length: 0x{:02x}".format(fo))

            part_len, size, partial = _parse_len(b)
            del b[:size]

            if partial:
                total = part_len
                while partial:
                    part_len, size, partial = _parse_len(b, total)
                    del b[total:total + size]
                    total += part_len
                self._len = total
            else:
                self._len = part_len

        def _old_len(b):
            if self.llen > 0:
                self._len = self.bytes_to_int(b[:self.llen])
                del b[:self.llen]

            else:  # pragma: no cover
                self._len = 0

        _new_len(val) if self._lenfmt == 1 else _old_len(val)

    @sdproperty
    def llen(self):
        lf = self._lenfmt

        if lf == 1:
            # new-format length
            if 192 > self.length:
                return 1

            elif 8384 > self.length:  # >= 192 is implied
                return 2

            else:
                return 5

        else:
            # old-format length
            ##TODO: what if _llen needs to be (re)computed?
            return self._llen

    @llen.register(int)
    def llen_int(self, val):
        if self._lenfmt == 0:
            self._llen = {0: 1, 1: 2, 2: 4, 3: 0}[val]

    def __init__(self):
        super().__init__()
        self._len = 1
        self._llen = 1
        self._lenfmt = 1
        self._partial = False


class DispatchGuidance(IntEnum):
    "Identify classes that should be left alone by PGPy's internal dispatch mechanism"
    NoDispatch = -1


class MetaDispatchable(abc.ABCMeta):
    """
    MetaDispatchable is a metaclass for objects that subclass Dispatchable
    """

    _roots: Set[Type] = set()
    """
    _roots is a set of all currently registered RootClass class objects

    A RootClass is successfully registered if the following things are true:
     - it inherits (directly or indirectly) from Dispatchable
     - __typeid__ is None
    """
    _registry: Dict[Union[Tuple[Type, Optional[IntEnum]], Tuple[Type, IntEnum, int]], Type] = {}
    """
    _registry is the Dispatchable class registry. It uses the following format:

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

    { (RootClass, TypeID): VerSubClass }:
        denotes that a given TypeID has multiple versions, and that this is class' subclasses handle those.
        A VerSubClass is registered identically to a normal SubClass.

    { (RootClass, TypeID, Ver): VerSubClass }:
        denotes the class that handles the type given in TypeID and the version of that type given in Ver

        a Versioned SubClass is successfully registered as such provided the following conditions are met:
         - it inherits from a VerSubClass
         - __ver__ > 0
         - the given typeid/ver combination is not already registered
    """

    def __new__(mcs, name, bases, attrs):  # NOQA
        ncls = super().__new__(mcs, name, bases, attrs)

        if ncls.__typeid__ is not DispatchGuidance.NoDispatch:
            if ncls.__typeid__ is None and not issubclass(ncls, tuple(MetaDispatchable._roots)):
                # this is a root class
                MetaDispatchable._roots.add(ncls)

            elif issubclass(ncls, tuple(MetaDispatchable._roots)):
                for rcls in (root for root in MetaDispatchable._roots if issubclass(ncls, root)):
                    if (rcls, ncls.__typeid__) not in MetaDispatchable._registry:
                        MetaDispatchable._registry[(rcls, ncls.__typeid__)] = ncls

                    if (
                        ncls.__ver__ is not None
                        and ncls.__ver__ > 0
                        and (rcls, ncls.__typeid__, ncls.__ver__) not in MetaDispatchable._registry
                    ):
                        MetaDispatchable._registry[(rcls, ncls.__typeid__, ncls.__ver__)] = ncls

        # finally, return the new class object
        return ncls

    def __call__(cls, packet=None):  # NOQA
        def _makeobj(cls):
            obj = object.__new__(cls)
            obj.__init__()
            return obj

        if packet is not None:
            if cls in MetaDispatchable._roots:
                rcls = cls

            elif issubclass(cls, tuple(MetaDispatchable._roots)):  # pragma: no cover
                rcls = next(root for root in MetaDispatchable._roots if issubclass(cls, root))

            ##TODO: else raise an exception of some kind, but this should never happen

            header = rcls.__headercls__()
            header.parse(packet)

            ncls = None
            if (rcls, header.typeid) in MetaDispatchable._registry:
                ncls = MetaDispatchable._registry[(rcls, header.typeid)]

                if ncls.__ver__ == 0:
                    if header.__class__ != ncls.__headercls__:
                        nh = ncls.__headercls__()
                        nh.__dict__.update(header.__dict__)
                        try:
                            nh.parse(packet)

                        except Exception as ex:
                            raise PGPError(str(ex)) from ex

                        header = nh

                    if (rcls, header.typeid, header.version) in MetaDispatchable._registry:
                        ncls = MetaDispatchable._registry[(rcls, header.typeid, header.version)]

                    else:  # pragma: no cover
                        ncls = None

            if ncls is None:
                ncls = MetaDispatchable._registry[(rcls, None)]

            obj = _makeobj(ncls)
            obj.header = header

            try:
                obj.parse(packet)

            except Exception as ex:
                raise PGPError(str(ex)) from ex

        else:
            obj = _makeobj(cls)

        return obj


class Dispatchable(PGPObject, metaclass=MetaDispatchable):
    __typeid__: Optional[IntEnum] = DispatchGuidance.NoDispatch

    @abc.abstractproperty
    def __headercls__(self):  # pragma: no cover
        return False

    __ver__: Optional[int] = None


class SignatureVerification:
    __slots__ = ("_subjects",)
    sigsubj = collections.namedtuple('sigsubj', ['issues', 'by', 'signature', 'subject'])

    @property
    def good_signatures(self):
        """
        A generator yielding namedtuples of all signatures that were successfully verified
        in the operation that returned this instance. The namedtuple has the following attributes:

        ``sigsubj.issues`` - ``SecurityIssues`` of whether the signature verified successfully or not. Must be 0 for success.

        ``sigsubj.by`` - the :py:obj:`~pgpy.PGPKey` that was used in this verify operation.

        ``sigsubj.signature`` - the :py:obj:`~pgpy.PGPSignature` that was verified.

        ``sigsubj.subject`` - the subject that was verified using the signature.
        """
        yield from (
            sigsub
            for sigsub in self._subjects
            if not sigsub.issues
            or (sigsub.issues and not sigsub.issues.causes_signature_verify_to_fail)
        )

    @property
    def bad_signatures(self):  # pragma: no cover
        """
        A generator yielding namedtuples of all signatures that were not verified
        in the operation that returned this instance. The namedtuple has the following attributes:

        ``sigsubj.verified`` - ``bool`` of whether the signature verified successfully or not.

        ``sigsubj.by`` - the :py:obj:`~pgpy.PGPKey` that was used in this verify operation.

        ``sigsubj.signature`` - the :py:obj:`~pgpy.PGPSignature` that was verified.

        ``sigsubj.subject`` - the subject that was verified using the signature.
        """
        yield from (
            sigsub
            for sigsub in self._subjects
            if sigsub.issues and sigsub.issues.causes_signature_verify_to_fail
        )

    def __init__(self):
        """
        Returned by :py:meth:`.PGPKey.verify`

        Can be compared directly as a boolean to determine whether or not the specified signature verified.
        """
        super().__init__()
        self._subjects = []

    def __contains__(self, item):
        return item in {ii for i in self._subjects for ii in [i.signature, i.subject]}

    def __len__(self):
        return len(self._subjects)

    def __bool__(self):
        from .constants import SecurityIssues
        return all(
            sigsub.issues is SecurityIssues.OK
            or (sigsub.issues and not sigsub.issues.causes_signature_verify_to_fail)
            for sigsub in self._subjects
        )

    def __and__(self, other):
        if not isinstance(other, SignatureVerification):
            raise TypeError(type(other))

        self._subjects += other._subjects
        return self

    def __repr__(self):
        return '<{classname}({val})>'.format(
            classname=self.__class__.__name__,
            val=bool(self)
        )

    def add_sigsubj(self, signature, by, subject=None, issues=None):
        if issues is None:
            from .constants import SecurityIssues
            issues = SecurityIssues(0xFF)
        self._subjects.append(self.sigsubj(issues, by, signature, subject))


class KeyID(str):
    '''
    This class represents an 8-octet key ID, which is used on the wire in a v3 PKESK packet.

    If a uint64 basic type existed in the stdlib, it would have been beter to use that instead.
    '''
    def __new__(cls, content: Union[str, bytes, bytearray]) -> "KeyID":
        if isinstance(content, str):
            if not re.match(r'^[0-9A-F]{16}$', content):
                raise ValueError(f'Initializing a KeyID from a string requires it to be 16 uppercase hex digits, not "{content}"')
            return str.__new__(cls, content)
        elif isinstance(content, (bytes, bytearray)):
            if len(content) != 8:
                raise ValueError(f'Initializing a KeyID from a bytes or bytearray requires exactly 8 bytes, not {content!r}')
            return str.__new__(cls, binascii.b2a_hex(content).decode('latin1').upper())
        else:
            raise TypeError(f'cannot initialize a KeyID from {type(content)}')

    @classmethod
    def from_bytes(cls, b: bytes) -> "KeyID":
        return cls(binascii.b2a_hex(b).decode('latin-1').upper())

    @classmethod
    def parse(cls, b: bytearray) -> "KeyID":
        'read a Key ID off the wire and consume the series of bytes that represent the Key ID.  Produces a new KeyID object'
        ret = cls.from_bytes(b[:8])
        del b[:8]
        return ret

    def __eq__(self, other: object) -> bool:
        if isinstance(other, KeyID):
            return str(self) == str(other)
        if isinstance(other, Fingerprint):
            return str(self) == str(other.keyid)
        if isinstance(other, str):
            if re.match(r'^[0-9A-F]{16}$', other):
                return str(self) == other
        if isinstance(other, bytes):
            return bytes(self) == other
        return False

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    def __int__(self) -> int:
        return int.from_bytes(bytes(self), byteorder='big', signed=False)

    def __hash__(self) -> int:
        return hash(str(self))

    def __bytes__(self) -> bytes:
        return binascii.a2b_hex(self)

    def __repr__(self) -> str:
        return f"KeyID({self})"


class Fingerprint(str):
    """
    A subclass of ``str``. Can be compared using == and != to ``str``, ``unicode``, and other :py:obj:`Fingerprint` instances.

    Primarily used as a key for internal dictionaries, so it ignores spaces when comparing and hashing
    """
    @property
    def keyid(self) -> KeyID:
        return KeyID(self[-16:])

    @property
    def shortid(self) -> str:
        if self._version != 4:
            raise ValueError("shortid can only ever be used on version 4 keys")
        return self[-8:]

    @sdproperty
    def version(self) -> int:
        'Returns None if the version is unknown'
        return self._version

    @version.register
    def version_int(self, version: int) -> None:
        self._version: int = version

    def __new__(cls, content: Union[str, bytes, bytearray], version=None) -> "Fingerprint":
        if isinstance(content, Fingerprint):
            return content

        if isinstance(content, (bytes, bytearray)):
            if len(content) != 20:
                raise ValueError(f'binary Fingerprint must be 20 bytes, not {len(content)}')
            return Fingerprint(binascii.b2a_hex(content).decode('latin-1').upper())
        # validate input before continuing: this should be a string of 40 hex digits
        content = content.upper().replace(' ', '')
        if not re.match(r'^[0-9A-F]{40}$', content):
            raise ValueError('Fingerprint must be a string of 40 hex digits')
        ret = str.__new__(cls, content)
        ret._version = 4 if version is None else version
        return ret

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Fingerprint):
            return str(self) == str(other) and self._version == other._version
        if isinstance(other, KeyID):
            return self.keyid == other

        if isinstance(other, (str, bytes, bytearray)):
            if isinstance(other, (bytes, bytearray)):  # pragma: no cover
                other = other.decode('latin-1')

            other = other.replace(' ', '')
            return any([str(self) == other,
                        self.keyid == other,
                        self._version == 4 and self.shortid == other])

        return False  # pragma: no cover

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        return hash(str(self))

    def __bytes__(self) -> bytes:
        return binascii.a2b_hex(self.encode("latin-1"))

    def __wireformat__(self) -> bytes:
        return bytes([self._version]) + bytes(self)

    def __pretty__(self) -> str:
        content = self
        if not bool(re.match(r'^[A-F0-9]{40}$', content)):
            raise ValueError("Expected: String of 40 hex digits")

        halves = [
            [content[i:i + 4] for i in range(0, 20, 4)],
            [content[i:i + 4] for i in range(20, 40, 4)]
        ]
        return '  '.join(' '.join(c for c in half) for half in halves)

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}v{self._version}({self.__pretty__()})'


class SorteDeque(collections.deque):
    """A deque subclass that tries to maintain sorted ordering using bisect"""

    def insort(self, item) -> None:
        i = bisect.bisect_left(self, item)
        self.rotate(- i)
        self.appendleft(item)
        self.rotate(i)

    def resort(self, item) -> None:  # pragma: no cover
        if item in self:
            # if item is already in self, see if it is still in sorted order.
            # if not, re-sort it by removing it and then inserting it into its sorted order
            i = bisect.bisect_left(self, item)
            if i == len(self) or self[i] is not item:
                self.remove(item)
                self.insort(item)

        else:
            # if item is not in self, just insert it in sorted order
            self.insort(item)

    def check(self) -> None:  # pragma: no cover
        """re-sort any items in self that are not sorted"""
        for unsorted in iter(self[i] for i in range(len(self) - 2) if not operator.le(self[i], self[i + 1])):
            self.resort(unsorted)


FingerprintValue = TypeVar('FingerprintValue')


class FingerprintDict(Generic[FingerprintValue], OrderedDict[Union[Fingerprint, KeyID, str], FingerprintValue]):
    '''An ordered collection of PGPKey objects indexable by either KeyID or fingerprint.

    Internally, they are all indexed by Fingerprint, but they can also
    be reached by KeyID, or by string representations of either Key
    ID or Fingerprint.

    '''
    @staticmethod
    def _normalize_input(k: Union[Fingerprint, KeyID, str]) -> Union[Fingerprint, KeyID]:
        if isinstance(k, (KeyID, Fingerprint)):
            return k
        if len(k) == 16:
            return KeyID(k)
        else:
            return Fingerprint(k)

    def _get_fpr_for_keyid(self, k: KeyID) -> Optional[Fingerprint]:
        # FIXME: if more than one fingerprint matches the key ID, what do we do?
        for fpr in super().keys():
            if not isinstance(fpr, Fingerprint):
                raise TypeError(f"keys should only be Fingerprint, somehow FingerprintDict got a key of type {type(fpr)}")
            if fpr.keyid == k:
                return fpr
        return None

    def __setitem__(self, k: Union[Fingerprint, KeyID, str], v: FingerprintValue) -> None:
        if not isinstance(k, Fingerprint):
            raise TypeError(f"items can only be added to a FingerprintDict by Fingerprint, not {type(k)}")
        return super().__setitem__(k, v)

    def __getitem__(self, k: Union[Fingerprint, KeyID, str]) -> FingerprintValue:
        k = FingerprintDict._normalize_input(k)
        if isinstance(k, Fingerprint):
            return super().__getitem__(k)
        fpr = self._get_fpr_for_keyid(k)
        if fpr is None:
            raise KeyError(k)
        return super().__getitem__(fpr)

    # FIXME: __getitem__ only replaces how the [] operator works.  The
    # "get" method only works by using Fingerprints.  Trying to
    # override get causes complaints from the typechecker.

    def __contains__(self, k: object):
        if not isinstance(k, (str, KeyID, Fingerprint)):
            raise TypeError(k)
        k = FingerprintDict._normalize_input(k)
        if isinstance(k, Fingerprint):
            return super().__contains__(k)
        return self._get_fpr_for_keyid(k) is not None
