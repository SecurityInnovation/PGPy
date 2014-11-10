""" test parsing packets
"""
import glob

from pgpy.packet import Packet
from pgpy.packet import Opaque


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
    # 0x0A: 'Marker', ##TODO: obtain one of these ##TODO: implement this
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
        return bytearray(ff.read())


class TestPacket(object):
    params = {
        # 'packet': sorted([ binload(os.path.abspath(f)) + b'\xca\xfe\xba\xbe'
        #                    for f in glob.glob('tests/testdata/packets/[0-9]*') ])
        'packet': sorted(glob.glob('tests/testdata/packets/[0-9]*'))
    }
    def test_load(self, packet):
        b = binload(packet) + b'\xca\xfe\xba\xbe'
        _b = b[:]
        p = Packet(_b)

        # parsed all bytes
        assert _b == b'\xca\xfe\xba\xbe'

        # length is computed correctly
        assert p.header.length + len(p.header) == len(p)
        assert len(p) == len(b) - 4
        assert len(p.__bytes__()) == len(b) - 4

        # __bytes__ output is correct
        assert p.__bytes__() == b[:-4]

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
