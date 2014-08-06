""" test parsing packets
"""
import pytest

import os
import re

from itertools import product

from pgpy.errors import PGPKeyDecryptionError

from pgpy.packet import Packet
from pgpy.packet import Opaque


from pgpy.constants import HashAlgorithm
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import String2KeyType
from pgpy.constants import SymmetricKeyAlgorithm

from pgpy.packet.types import Header
from pgpy.packet.fields import String2Key

pdir = 'tests/testdata/packets/'

def pytest_generate_tests(metafunc):
    if 'packet' in metafunc.fixturenames:
        packetfiles = sorted([ pdir + f for f in os.listdir(pdir) ])
        argvals = [bytearray(os.path.getsize(p)) for p in packetfiles]
        for i, pf in enumerate(packetfiles):
            with open(pf, 'rb') as p:
                p.readinto(argvals[i])
        ids = [ '_'.join(re.split('\.', pf)[1:]) for pf in packetfiles]
        metafunc.parametrize('packet', argvals, ids=ids, scope="class")

    if 'ekpacket' in metafunc.fixturenames:
        packetfiles = sorted([ pdir + f for f in os.listdir(pdir) if 'enc' in f ])
        argvals = [bytearray(os.path.getsize(p)) for p in packetfiles]
        for i, pf in enumerate(packetfiles):
            with open(pf, 'rb') as p:
                p.readinto(argvals[i])
        ids = [ '_'.join(re.split('\.', pf)[1:]) for pf in packetfiles]
        metafunc.parametrize('ekpacket', argvals, ids=ids, scope="class")

_pclasses = {
    # 0x01: [''], ##TODO: name this
    0x02: ['SignatureV4'],
    # 0x03: [''], ##TODO: name this
    # 0x04: [''], ##TODO: name this
    0x05: ['PrivKeyV4'],
    0x06: ['PubKeyV4'],
    0x07: ['PrivSubKeyV4'],
    # 0x08: ['CompressedData'], ##TODO: uncomment when class is turned back on
    # 0x09: [''], ##TODO: name this
    # 0x0A: [''], ##TODO: name this
    # 0x0B: ['LiteralData'], ##TODO: uncomment when class is written
    # 0x0C: ['Trust'], ##TODO: uncomment when class is turned back on
    # 0x0D: ['UserID'], ##TODO: uncomment when class is turned back on
    0x0E: ['PubSubKeyV4'],
    # 0x11: ['UserAttribute'], ##TODO: uncomment when class is turned back on
    # 0x12: [''], ##TODO: name this
    # 0x13: ['',] ##TODO: name this
}

class TestPacket(object):
    @pytest.mark.parametrize('b',
        [ # new format
          # 1 byte length - 191
          bytearray(b'\xc2' + b'\xbf' +                 (b'\x00' * 191)),
          # 2 byte length - 192
          bytearray(b'\xc2' + b'\xc0\x00' +             (b'\x00' * 192)),
          # 2 byte length - 8383
          bytearray(b'\xc2' + b'\xdf\xff' +             (b'\x00' * 8383)),
          # 5 byte length - 8384
          bytearray(b'\xc2' + b'\xff\x00\x00 \xc0' +    (b'\x00' * 8384)),
          # old format
          # 1 byte length - 255
          bytearray(b'\x88' + b'\xff' +                 (b'\x00' * 255)),
          # 2 byte length - 256
          bytearray(b'\x89' + b'\x01\x00' +             (b'\x00' * 256)),
          # 4 byte length - 65536
          bytearray(b'\x8a' + b'\x00\x01\x00\x00' +     (b'\x00' * 65536)),
        ])
    def test_header(self, b):
        _b = b[:]
        h = Header()
        h.parse(b)

        assert h.tag == 0x02
        assert h.length == len(b)
        assert len(h) == len(_b) - len(b)
        assert bytes(h) == _b[:len(h)]

    @pytest.mark.parametrize('b',
        [ (bytearray(i) +
           b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF') # iv
          for i in product(b'\xff',                                         # usage
                           b'\x01\x02\x03\x04\x07\x08\x09\x0B\x0C\x0D',     # symmetric cipher algorithm
                           b'\x00',                                         # specifier (simple)
                           b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B') # hash algorithm
        ])
    def test_simple_string2key(self, b):
        _b = b[:]
        s = String2Key()
        s.parse(b)

        assert len(b) == 0
        assert len(s) == len(_b)
        assert bytes(s) == bytes(_b)

        assert bool(s)
        assert s.halg in HashAlgorithm
        assert s.encalg in SymmetricKeyAlgorithm
        assert s.specifier == String2KeyType.Simple
        assert s.iv == b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'

    @pytest.mark.parametrize('b',
        [ (bytearray(i) +
           b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE' + # salt
           b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF')  # iv
          for i in product(b'\xff',                                         # usage
                           b'\x01\x02\x03\x04\x07\x08\x09\x0B\x0C\x0D',     # symmetric cipher algorithm
                           b'\x01',                                         # specifier (salted)
                           b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B') # hash algorithm

        ])
    def test_salted_string2key(self, b):
        _b = b[:]
        s = String2Key()
        s.parse(b)

        assert len(b) == 0
        assert len(s) == len(_b)
        assert bytes(s) == bytes(_b)

        assert bool(s)
        assert s.halg in HashAlgorithm
        assert s.encalg in SymmetricKeyAlgorithm
        assert s.specifier == String2KeyType.Salted
        assert s.salt == b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE'
        assert s.iv == b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'

    @pytest.mark.parametrize('b',
        [ (bytearray(i) +
           b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE' + # salt
           b'\x10' +                             # count
           b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF')  # iv
          for i in product(b'\xff',                                         # usage
                           b'\x01\x02\x03\x04\x07\x08\x09\x0A\x0B\x0C\x0D', # symmetric cipher algorithm
                           b'\x03',                                         # specifier (iterated)
                           b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B') # hash algorithm

        ])
    def test_iterated_string2key(self, b):
        _b = b[:]
        s = String2Key()
        s.parse(b)

        assert len(b) == 0
        assert len(s) == len(_b)
        assert bytes(s) == bytes(_b)

        assert bool(s)
        assert s.halg in HashAlgorithm
        assert s.encalg in SymmetricKeyAlgorithm
        assert s.specifier == String2KeyType.Iterated
        assert s.salt == b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE'
        assert s.count == 2048
        assert s.iv == b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'

    def test_load(self, packet):
        b = packet[:]
        p = Packet(packet)

        # parsed all bytes
        assert len(packet) == 0

        # length is computed correctly
        assert p.header.length + len(p.header) == len(p)
        assert len(p) == len(b)
        assert len(bytes(p)) == len(bytes(b))

        # __bytes__ output is correct
        assert bytes(p) == bytes(b)

        # instantiated class is what we expected
        if p.header.tag in _pclasses:
            assert p.__class__.__name__ in _pclasses[p.header.tag]

        else:
            assert isinstance(p, Opaque)

    def test_decrypt(self, ekpacket):
        p = Packet(ekpacket)

        if p.pkalg == PubKeyAlgorithm.RSAEncryptOrSign:
            assert p.secmaterial.d == bytearray()
            assert p.secmaterial.p == bytearray()
            assert p.secmaterial.q == bytearray()
            assert p.secmaterial.u == bytearray()

        if p.pkalg in [PubKeyAlgorithm.DSA, PubKeyAlgorithm.ElGamal]:
            assert p.secmaterial.x == bytearray()

        with pytest.raises(PGPKeyDecryptionError):
            p.unprotect("TheWrongPassword")

        p.unprotect("QwertyUiop")

        if p.pkalg == PubKeyAlgorithm.RSAEncryptOrSign:
            assert len(p.secmaterial.d) > 0
            assert len(p.secmaterial.p) > 0
            assert len(p.secmaterial.q) > 0
            assert len(p.secmaterial.u) > 0

        if p.pkalg in [PubKeyAlgorithm.DSA, PubKeyAlgorithm.ElGamal]:
            assert len(p.secmaterial.x) > 0
