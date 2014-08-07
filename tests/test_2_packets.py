""" test parsing packets
"""
from __future__ import unicode_literals
import pytest

import sys

from pgpy.errors import PGPKeyDecryptionError

from pgpy.packet import Packet
from pgpy.packet import Opaque

from pgpy.constants import PubKeyAlgorithm


_pclasses = {
    # 0x01: [''], ##TODO: name this
    (0x02, 4): 'SignatureV4',
    # 0x03: [''], ##TODO: name this
    # 0x04: [''], ##TODO: name this
    (0x05, 4): 'PrivKeyV4',
    (0x06, 4): 'PubKeyV4',
    (0x07, 4): 'PrivSubKeyV4',
    # 0x08: ['CompressedData'], ##TODO: uncomment when class is turned back on
    # 0x09: [''], ##TODO: name this
    # 0x0A: [''], ##TODO: name this
    # 0x0B: ['LiteralData'], ##TODO: uncomment when class is written
    0x0C: 'Trust',
    0x0D: 'UserID',
    (0x0E, 4): 'PubSubKeyV4',
    0x11: 'UserAttribute',
    # 0x12: [''], ##TODO: name this
    # 0x13: ['',] ##TODO: name this
}

class TestPacket(object):
    def test_load(self, packet):
        b = packet[:]
        p = Packet(packet)

        # parsed all bytes
        # assert len(packet) == 0
        assert packet == b'\xca\xfe\xba\xbe'

        # length is computed correctly
        assert p.header.length + len(p.header) == len(p)
        assert len(p) == len(b) - 4
        assert len(bytes(p)) == len(bytes(b)) - 4

        # __bytes__ output is correct
        assert bytes(p) == bytes(b[:-4])

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

        sys.stdout.write("[{cname:s}] ".format(cname=p.__class__.__name__))

    def test_decrypt_enckey(self, ekpacket, ukpacket):
        # parse the encrypted and decrypted version
        ep = Packet(ekpacket)
        up = Packet(ukpacket)

        # verify that we are comparing the same key
        assert ep.fingerprint == up.fingerprint

        # verify that ep's secmaterial fields are empty

        if ep.pkalg == PubKeyAlgorithm.RSAEncryptOrSign:
            assert ep.secmaterial.d == bytearray()
            assert ep.secmaterial.p == bytearray()
            assert ep.secmaterial.q == bytearray()
            assert ep.secmaterial.u == bytearray()
        if ep.pkalg in [PubKeyAlgorithm.DSA, PubKeyAlgorithm.ElGamal]:
            assert ep.secmaterial.x == bytearray()

        # verify trying to unprotect using the wrong password doesn't work
        # also try with a purposely unicode password
        with pytest.raises(PGPKeyDecryptionError):
            ep.unprotect("TheWrongPassword")
            # Mañana
            ep.unprotect("Ma\u00F1ana")

        # now unprotect with the correct password
        ep.unprotect("QwertyUiop")

        # and verify that it matches the unencrypted version
        if ep.pkalg == PubKeyAlgorithm.RSAEncryptOrSign:
            assert ep.secmaterial.d == up.secmaterial.d
            assert ep.secmaterial.p == up.secmaterial.p
            assert ep.secmaterial.q == up.secmaterial.q
            assert ep.secmaterial.u == up.secmaterial.u
        if ep.pkalg in [PubKeyAlgorithm.DSA, PubKeyAlgorithm.ElGamal]:
            assert ep.secmaterial.x == up.secmaterial.x
