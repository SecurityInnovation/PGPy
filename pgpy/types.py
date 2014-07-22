""" types.py
"""
import abc
import base64
import collections
import os
import re

from enum import Enum

import requests

from ._author import __version__

from .errors import PGPError

from .util import bytes_to_int
from .util import int_to_bytes
from .util import is_ascii
from .util import is_path

try:  # pragma: no cover
    e = FileNotFoundError
except NameError:  # pragma: no cover
    e = IOError


# class Magic(Enum):
#     Signature = 'SIGNATURE'
#     PubKey = 'PUBLIC KEY BLOCK'
#     PrivKey = 'PRIVATE KEY BLOCK'
#
#     def __str__(self):
#         return self.name


class FileLoader(object):
    __metaclass__ = abc.ABCMeta

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

    @abc.abstractmethod
    def __bytes__(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def __str__(self):
        raise NotImplementedError()

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


class PGPObject(FileLoader):
    __metaclass__ = abc.ABCMeta

    __crc24_init = 0x0B704CE
    __crc24_poly = 0x1864CFB

    __armor_fmt = '-----BEGIN PGP {block_type}-----\n' \
                  '{headers}\n' \
                  '{packet}\n' \
                  '={crc}\n' \
                  '-----END PGP {block_type}-----\n'

    @abc.abstractproperty
    def magic(self):
        """The magic string identifier for the current PGP type"""
        raise NotImplementedError()

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

        if type(text) is bytes:
            text = text.decode()

        armor_reg = r'^-----BEGIN PGP (?P<magic>[A-Z ]*)-----$\n' \
                    r'((?=.+: .+\n\n)(?P<headers>.*)\n\n)?' \
                    r'(?P<body>[A-Za-z0-9+/\n]+=*)\n' \
                    r'^=(?P<crc>[A-Za-z0-9+/]{4})\n' \
                    r'^-----END PGP (?P=magic)-----$\n'
        m = re.match(armor_reg, text, flags=re.MULTILINE | re.DOTALL)

        if m is None:
            raise ValueError("Expected: ASCII-armored PGP data")

        m = m.groupdict()

        if m['headers'] is not None:
            m['headers'] = collections.OrderedDict(re.findall('^(?P<key>.+): (?P<value>.+)$\n?', m['headers'], flags=re.MULTILINE))

        if m['body'] is not None:
            m['body'] = base64.b64decode(m['body'].encode())

        if m['crc'] is not None:
            m['crc'] = bytes_to_int(base64.b64decode(m['crc'].encode()))

        return m

    @classmethod
    def new(cls):
        return cls()

    @classmethod
    def load(cls, data):
        new = cls.new()

        d = {'magic': None, 'headers': None, 'body': None, 'crc': None}

        if is_path(data) and (os.path.isfile(data) or os.path.isdir(os.path.dirname(data))):
            new.path = os.path.abspath(data)

        try:
            d = PGPObject.ascii_unarmor(super(PGPObject, cls).load(data))

        except ValueError:
            d['body'] = super(PGPObject, cls).load(data)

        finally:
            # check magic
            if d['magic'] != new.magic:
                raise PGPError("Wrong type of data. Got: {}; Expected: {}".format(d['magic'], new.magic))

            # check the CRC24
            if d['crc'] != new.crc24(d['body']):
                raise PGPError("Bad CRC")

            # load headers
            if d['headers'] is not None:
                new.ascii_headers = d['headers']

            # parse!
            new.parse(d['body'])

        return new

    def __init__(self):
        super(PGPObject, self).__init__()
        self.ascii_headers = collections.OrderedDict()
        self.ascii_headers['Version'] = 'PGPy v' + __version__ # Default value

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

    @abc.abstractmethod
    def parse(self, data):
        raise NotImplementedError()

    def __str__(self):
        payload = base64.b64encode(self.__bytes__()).decode()
        payload = '\n'.join([ payload[i:(i + 64)] for i in range(0, len(payload), 64) ])

        return self.__armor_fmt.format(
            block_type=self.magic,
            headers=''.join([ '{key}: {val}\n'.format(key=key, val=val) for key, val in self.ascii_headers.items() ]),
            packet=payload,
            crc=base64.b64encode(int_to_bytes(self.crc24(), 3)).decode()
        )

    @abc.abstractmethod
    def __pgpdump__(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def __bytes__(self):
        raise NotImplementedError()


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
