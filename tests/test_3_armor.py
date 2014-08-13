""" test (de)armoring of PGP blocks
"""
import pytest

from datetime import datetime

from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import HashAlgorithm
from pgpy.constants import SignatureType

from pgpy.pgp import PGPSignature
from pgpy.pgp import PGPKey

from pgpy.types import Exportable


# generic block tests
class TestBlocks(object):
    def test_load(self, block):
        if 'SIGNATURE' in block.decode('latin-1').splitlines()[0]:
            p1 = PGPSignature()
            p2 = PGPSignature()

        elif 'KEY' in block.decode('latin-1').splitlines()[0]:
            pytest.skip("not ready for this one")
            p1 = PGPKey()
            p2 = PGPKey()

        else:
            pytest.skip("not ready for this one")
            assert False

        # load ASCII
        p1.parse(block)
        # manually de-armor and load the binary data
        p2.parse(Exportable.ascii_unarmor(block)['body'])


# PGPSignature specific tests
class TestPGPSignature(object):
    def test_load_rsa(self, rsasigblock):
        p = PGPSignature()
        p.parse(rsasigblock)

        # check member and property output
        assert p._signature is not None
        assert p.__sig__ == b'\x70\x38\x79\xd0\x58\x70\x58\x7b\x50\xe6\xab\x8f\x9d\xc3\x46\x2c\x5a\x6b\x98\x96\xcf\x3b' \
                            b'\xa3\x79\x13\x08\x6d\x90\x9d\x67\xd2\x48\x7d\xd7\x1a\xa5\x98\xa7\x8f\xca\xe3\x24\xd4\x19' \
                            b'\xab\xe5\x45\xc5\xff\x21\x0c\x72\x88\x91\xe6\x67\xd7\xe5\x00\xb3\xf5\x55\x0b\xd0\xaf\x77' \
                            b'\xb3\x7e\xa4\x79\x59\x06\xa2\x05\x44\x9d\xd2\xa9\xcf\xb1\xf8\x03\xc1\x90\x81\x87\x36\x1a' \
                            b'\xa6\x5c\x79\x98\xfe\xdb\xdd\x23\x54\x69\x92\x2f\x0b\xc4\xee\x2a\x61\x77\x35\x59\x6e\xb2' \
                            b'\xe2\x1b\x80\x61\xaf\x2d\x7a\x64\x38\xfe\xe3\x95\xcc\xe8\xa4\x05\x55\x5d'
        assert p.created == datetime.utcfromtimestamp(1402615373)
        assert p.expired is False
        assert p.exportable is True
        assert p.features == []
        assert p.hash2 == b'\xc4\x24'
        assert p.hash_algorithm == HashAlgorithm.SHA512
        assert p.key_algorithm == PubKeyAlgorithm.RSAEncryptOrSign
        assert p.key_flags == []
        assert p.magic == "SIGNATURE"
        assert p.notation == {}
        assert p.prefs == {}
        assert p.revocable is True
        assert p.revocation_key is None
        # assert p.revoked is False  # not implemented yet
        assert p.signer == 'FCAE54F74BA27CF7'
        # assert p.target_signature is None  # not implemented yet
        assert p.type == SignatureType.BinaryDocument
        assert p.__bytes__() == bytes(Exportable.ascii_unarmor(rsasigblock)['body'])



# PGPKey specific tests
class TestPGPKey(object):
    pass
