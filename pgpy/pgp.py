""" pgp.py

"""
import re
import collections
import base64

from .fileloader import FileLoader
from .reg import *
from .util import bytes_to_int, int_to_bytes
from .packet import PGPPacket

ASCII_FORMAT = \
    "-----BEGIN PGP {block_type}-----\n"\
    "{headers}\n"\
    "{packet}\n"\
    "={crc}\n"\
    "-----END PGP {block_type}-----\n"


class PGPBlock(FileLoader):
    crc24_init = 0xB704CE
    crc24_poly = 0x1864CFB

    @staticmethod
    def extract_pgp_ascii_block(data, btype=None):
        if type(data) is bytes:
            data = data.decode()

        pgpiter = re.finditer(ASCII_ARMOR_BLOCK_REG, data, flags=re.MULTILINE | re.DOTALL)

        if btype is None:
            return pgpiter

        for m in pgpiter:
            block = data[m.start():m.end()]

            # specific type
            if re.match(Magic(btype).value, block):
                return block.encode()

        # nothing found :(
        return b''

    def __init__(self, data, btype):
        self.type = btype
        self.ascii_headers = collections.OrderedDict()
        self.data = b''
        self.crc = 0
        self.packets = []

        super(PGPBlock, self).__init__(data)

    def parse(self):
        # try to extract the signature block
        self.bytes = self.extract_pgp_ascii_block(self.bytes, self.type)

        # parsing/decoding using the RFC 4880 section on "Forming ASCII Armor"
        # https://tools.ietf.org/html/rfc4880#section-6.2
        k = re.split(ASCII_ARMOR_BLOCK_REG, self.bytes.decode(), flags=re.MULTILINE | re.DOTALL)[1:-1]

        # parse header field(s)
        h = [ h for h in re.split(r'^([^:]*): (.*)$\n?', k[1], flags=re.MULTILINE) if h != '' ]
        for key, val in [ (h[i], h[i+1]) for i in range(0, len(h), 2) ]:
            self.ascii_headers[key] = val

        self.data = base64.b64decode(k[2].replace('\n', '').encode())
        self.crc = bytes_to_int(base64.b64decode(k[3].encode()))

        # verify CRC
        if self.crc != self.crc24():
            raise Exception("Bad CRC")

        # dump fields in all contained packets per RFC 4880, without using pgpdump
        pos = 0
        while pos < len(self.data):
            self.packets.append(PGPPacket(self.data[pos:]))
            pos += len(self.packets[-1].__bytes__())


    def crc24(self):
        # CRC24 computation, as described in the RFC 4880 section on Radix-64 Conversions
        #
        # The checksum is a 24-bit Cyclic Redundancy Check (CRC) converted to
        # four characters of radix-64 encoding by the same MIME base64
        # transformation, preceded by an equal sign (=).  The CRC is computed
        # by using the generator 0x864CFB and an initialization of 0xB704CE.
        # The accumulation is done on the data before it is converted to
        # radix-64, rather than on the converted data.
        if self.data == b'':
            return None

        crc = self.crc24_init
        sig = [ ord(i) for i in self.data ] if type(self.data) is str else self.data

        for loc in range(0, len(self.data)):
            crc ^= sig[loc] << 16

            for i in range(0, 8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= self.crc24_poly

        return crc & 0xFFFFFF

    def __str__(self):
        headers = ""
        for key, val in self.ascii_headers.items():
            headers += "{key}: {val}\n".format(key=key, val=val)

        # base64-encode our bytes, then insert a newline every 64th character
        payload = b''
        for pkt in self.packets:
            payload += pkt.__bytes__()
        payload = base64.b64encode(payload).decode()
        payload = '\n'.join(payload[i:i+64] for i in range(0, len(payload), 64))

        return ASCII_FORMAT.format(
                block_type=str(self.type),
                headers=headers,
                packet=payload,
                crc=base64.b64encode(int_to_bytes(self.crc, 3)).decode(),
            )
