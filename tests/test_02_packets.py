""" test parsing packets
"""
import pytest

import glob
import os

from pgpy.packet import Packet
from pgpy.packet import PubKeyV4, PubSubKeyV4, PrivKeyV4, PrivSubKeyV4
from pgpy.packet import Opaque

# import pgpy.packet.fields

_trailer = b'\xde\xca\xff\xba\xdd'
_pclasses = {
    (0x01, 3): 'PKESessionKeyV3',
    (0x02, 4): 'SignatureV4',
    (0x03, 4): 'SKESessionKeyV4',
    (0x04, 3): 'OnePassSignatureV3',
    (0x05, 4): 'PrivKeyV4',
    (0x06, 4): 'PubKeyV4',
    (0x07, 4): 'PrivSubKeyV4',
    0x08: 'CompressedData',
    0x09: 'SKEData',
    0x0A: 'Marker',
    0x0B: 'LiteralData',
    0x0C: 'Trust',
    0x0D: 'UserID',
    (0x0E, 4): 'PubSubKeyV4',
    0x11: 'UserAttribute',
    (0x12, 1): 'IntegrityProtectedSKEDataV1',
    0x13: 'MDC',
}


def binload(f):
    with open(f, 'rb') as ff:
        buf = bytearray(os.fstat(ff.fileno()).st_size)
        ff.readinto(buf)
        return buf


pktfiles = sorted(glob.glob('tests/testdata/packets/[0-9]*'))


class TestPacket(object):
    @pytest.mark.parametrize('packet', pktfiles, ids=[os.path.basename(f) for f in pktfiles])
    def test_load(self, packet):
        b = binload(packet) + _trailer
        _b = b[:]
        p = Packet(_b)

        # parsed all bytes
        assert _b == _trailer

        # length is computed correctly
        assert p.header.length + len(p.header) == len(p)
        if packet not in ('tests/testdata/packets/11.partial.literal',):
            assert len(p) == len(b) - len(_trailer)
            assert len(p.__bytes__()) == len(b) - len(_trailer)

            # __bytes__ output is correct
            assert p.__bytes__() == b[:-len(_trailer)]

        # instantiated class is what we expected
        if hasattr(p.header, 'version') and (p.header.tag, p.header.version) in _pclasses:
            # versioned packet
            assert p.__class__.__name__ == _pclasses[(p.header.tag, p.header.version)]

        elif (not hasattr(p.header, 'version')) and p.header.tag in _pclasses:
            # unversioned packet
            assert p.__class__.__name__ in _pclasses[p.header.tag]

        else:
            # fallback to opaque
            assert isinstance(p, Opaque)

        # if this is a key, ensure len(p.keymaterial) == len(bytes(p.keymaterial))
        if isinstance(p, (PubKeyV4, PubSubKeyV4, PrivKeyV4, PrivSubKeyV4)):
            assert len(p.keymaterial) == len(p.keymaterial.__bytes__())
