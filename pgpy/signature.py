""" signature.py

PGP Signature parsing
"""
import base64
import collections
import re
import hashlib

from .packet import PGPPacket
from .fileloader import FileLoader
from .util import bytes_to_int, int_to_bytes
from . import ASCII_ARMOR_BLOCK_REG, ASCII_ARMOR_BLOCK_FORMAT


class PGPSignature(FileLoader):
    crc24_init = 0xB704CE
    crc24_poly = 0x1864CFB

    def __init__(self, sigf):
        self.ascii_headers = collections.OrderedDict()
        self.signature_packet = None
        self.crc = None
        self.fields = None

        super(PGPSignature, self).__init__(sigf)
        ##TODO: handle creating a new signature

    def parse(self):
        # nothing to parse; this is a new signature
        if self.bytes == b'':
            return

        # parsing/decoding using the RFC 4880 section on "Forming ASCII Armor"
        # https://tools.ietf.org/html/rfc4880#section-6.2
        k = re.split(ASCII_ARMOR_BLOCK_REG.replace('%BLOCK_TYPE%', 'PGP SIGNATURE'),
                     self.bytes.decode(), flags=re.MULTILINE | re.DOTALL)[1:-1]

        # parse header field(s)
        h = [ h for h in re.split(r'^([^:]*): (.*)$\n?', k[0], flags=re.MULTILINE) if h != '' ]
        for key, val in [ (h[i], h[i+1]) for i in range(0, len(h), 2) ]:
            self.ascii_headers[key] = val

        self.signature_packet = base64.b64decode(k[1].replace('\n', '').encode())
        self.crc = bytes_to_int(base64.b64decode(k[2].encode()))

        # verify CRC
        if self.crc != self.crc24():
            raise Exception("Bad CRC")

        # dump fields in signature_packet per RFC 4880, without using pgpdump
        self.fields = PGPPacket(self.signature_packet)

    def crc24(self):
        # CRC24 computation, as described in the RFC 4880 section on Radix-64 Conversions
        #
        # The checksum is a 24-bit Cyclic Redundancy Check (CRC) converted to
        # four characters of radix-64 encoding by the same MIME base64
        # transformation, preceded by an equal sign (=).  The CRC is computed
        # by using the generator 0x864CFB and an initialization of 0xB704CE.
        # The accumulation is done on the data before it is converted to
        # radix-64, rather than on the converted data.
        if self.signature_packet is None:
            return None

        crc = self.crc24_init
        sig = [ ord(i) for i in self.signature_packet ] if type(self.signature_packet) is str else self.signature_packet

        for loc in range(0, len(self.signature_packet)):
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

        # base64-encode self.signature_packet, then insert a newline every 64th character
        payload = base64.b64encode(self.signature_packet).decode()
        payload = '\n'.join(payload[i:i+64] for i in range(0, len(payload), 64))

        return ASCII_ARMOR_BLOCK_FORMAT.format(
                block_type="PGP SIGNATURE",
                headers=headers,
                packet=payload,
                crc=base64.b64encode(int_to_bytes(self.crc)).decode(),
            )

    def __bytes__(self):
        return self.fields.__bytes__()