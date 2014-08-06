""" test parsing packets
"""
import pytest

from pgpy.errors import PGPKeyDecryptionError

from pgpy.packet import Packet
from pgpy.packet import Opaque

from pgpy.constants import PubKeyAlgorithm


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
    0x0C: ['Trust'],
    0x0D: ['UserID'],
    0x0E: ['PubSubKeyV4'],
    # 0x11: ['UserAttribute'], ##TODO: uncomment when class is turned back on
    # 0x12: [''], ##TODO: name this
    # 0x13: ['',] ##TODO: name this
}

class TestPacket(object):
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

    def test_decrypt_enckey(self, ekpacket):
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
