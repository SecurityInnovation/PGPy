""" test parsing packets
"""
import pytest

import os
import re

from pgpy.packet.fields import Header
from pgpy.packet import Packet
from pgpy.packet import Opaque

pdir = 'tests/testdata/packets/'

def pytest_generate_tests(metafunc):
    if 'packet' in metafunc.fixturenames:
        packetfiles = sorted([ pdir + f for f in os.listdir(pdir) ])
        argvals = [bytearray(os.path.getsize(p)) for p in packetfiles]
        for i, pf in enumerate(packetfiles):
            with open(pf, 'rb') as p:
                p.readinto(argvals[i])
        ids = [ re.split('\.', pf)[1] for pf in packetfiles]
        metafunc.parametrize('packet', argvals, ids=ids, scope="class")

_pclasses = {
    # 0x01: '', ##TODO: name this
    # 0x02: 'Signature', ##TODO: uncomment when class is turned back on
    # 0x03: '', ##TODO: name this
    # 0x04: '', ##TODO: name this
    # 0x05: 'PrivKey', ##TODO: uncomment when class is turned back on
    # 0x06: 'PubKey', ##TODO: uncomment when class is turned back on
    # 0x07: 'PrivSubKey', ##TODO: uncomment when class is turned back on
    # 0x08: 'CompressedData', ##TODO: uncomment when class is turned back on
    # 0x09: '', ##TODO: name this
    # 0x0A: '', ##TODO: name this
    # 0x0B: 'LiteralData', ##TODO: uncomment when class is turned back on
    # 0x0C: 'Trust', ##TODO: uncomment when class is turned back on
    # 0x0D: 'UserID', ##TODO: uncomment when class is turned back on
    # 0x0E: 'PubSubKey', ##TODO: uncomment when class is turned back on
    # 0x11: 'UserAttribute', ##TODO: uncomment when class is turned back on
    # 0x12: '', ##TODO: name this
    # 0x13: '', ##TODO: name this
}

class TestPacket(object):
    @pytest.mark.parametrize('b',
        [ bytearray(b'\xc2' + b'\xbf' +                 (b'\x00' * 191)),   # 1 byte length - 191   - new format
          bytearray(b'\xc2' + b'\xc0\x00' +             (b'\x00' * 192)),   # 2 byte length - 192   - new format
          bytearray(b'\xc2' + b'\xdf\xff' +             (b'\x00' * 8383)),  # 2 byte length - 8383  - new format
          bytearray(b'\xc2' + b'\xff\x00\x00 \xc0' +    (b'\x00' * 8384)),  # 5 byte length - 8384  - new format
          bytearray(b'\x88' + b'\xff' +                 (b'\x00' * 255)),   # 1 byte length - 255   - old format
          bytearray(b'\x89' + b'\x01\x00' +             (b'\x00' * 256)),   # 2 byte length - 256   - old format
          bytearray(b'\x8a' + b'\x00\x01\x00\x00' +     (b'\x00' * 65536)), # 4 byte length - 65536 - old format
        ])
    def test_header(self, b):
        _b = b[:]
        h = Header()
        h.parse(b)

        assert h.tag == 0x02
        assert h.length == len(b)
        assert len(h) == len(_b) - len(b)
        assert bytes(h) == _b[:len(h)]

    def test_load(self, packet):
        b = packet[:]
        p = Packet(packet)

        assert p.header.length + len(p.header) == len(p)
        assert len(p) == len(bytes(b))
        assert bytes(p) == bytes(b)

        if p.header.tag in _pclasses:
            assert p.__class__.__name__ == _pclasses[p.header.tag]

        else:
            assert isinstance(p, Opaque)

