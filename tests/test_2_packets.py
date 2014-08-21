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
    (0x01, 3): 'PKESessionKeyV3',
    (0x02, 4): 'SignatureV4',
    # (0x03, 4): 'SKESessionKeyV4', ##TODO: implement this
    # (0x04, 4): 'OnePassSignatureV4', ##TODO: implement this
    (0x05, 4): 'PrivKeyV4',
    (0x06, 4): 'PubKeyV4',
    (0x07, 4): 'PrivSubKeyV4',
    0x08: 'CompressedData',
    # 0x09: 'SKEData', ##TODO: implement this
    # 0x0A: 'Marker', ##TODO: obtain one of these ##TODO: implement this
    0x0B: 'LiteralData',
    0x0C: 'Trust',
    0x0D: 'UserID',
    (0x0E, 4): 'PubSubKeyV4',
    0x11: 'UserAttribute',
    (0x12, 1): 'IntegrityProtectedSKEDataV1', ##TODO: implement this
    # 0x13: 'MDC', ##TODO: obtain one of these ##TODO: implement this
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

        sys.stdout.write("[{cname:s}] ".format(cname=p.__class__.__name__))

    def test_decrypt_enckey(self, ekpacket, ukpacket):
        # parse the encrypted and decrypted version
        ep = Packet(ekpacket)
        up = Packet(ukpacket)

        # verify that we are comparing the same key
        assert ep.fingerprint == up.fingerprint

        # verify that ep's secmaterial fields are empty

        if ep.pkalg == PubKeyAlgorithm.RSAEncryptOrSign:
            assert ep.keymaterial.d == 0
            assert ep.keymaterial.p == 0
            assert ep.keymaterial.q == 0
            assert ep.keymaterial.u == 0
        if ep.pkalg in [PubKeyAlgorithm.DSA, PubKeyAlgorithm.ElGamal]:
            assert ep.keymaterial.x == 0

        # verify trying to unprotect using the wrong password doesn't work
        # also try with a purposely unicode password
        with pytest.raises(PGPKeyDecryptionError):
            ep.unprotect("TheWrongPassword")
            ep.unprotect("Ma\u00F1ana")

        # now unprotect with the correct password
        ep.unprotect("QwertyUiop")

        # and verify that it matches the unencrypted version
        if ep.pkalg == PubKeyAlgorithm.RSAEncryptOrSign:
            assert ep.keymaterial.d == up.keymaterial.d
            assert ep.keymaterial.p == up.keymaterial.p
            assert ep.keymaterial.q == up.keymaterial.q
            assert ep.keymaterial.u == up.keymaterial.u
        if ep.pkalg in [PubKeyAlgorithm.DSA, PubKeyAlgorithm.ElGamal]:
            assert ep.keymaterial.x == up.keymaterial.x
