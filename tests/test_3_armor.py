""" test (de)armoring of PGP blocks
"""
import pytest

from datetime import datetime

from pgpy.constants import CompressionAlgorithm
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SignatureType
from pgpy.constants import SymmetricKeyAlgorithm

from pgpy.pgp import PGPKey
from pgpy.pgp import PGPMessage
from pgpy.pgp import PGPSignature

from pgpy.types import Exportable


# generic block tests
class TestBlocks(object):
    def test_load(self, block):
        if 'SIGNATURE' in block.splitlines()[0]:
            p = PGPSignature()

        elif 'KEY' in block.splitlines()[0]:
            p = PGPKey()


        # elif 'SIGNED MESSAGE' in block.splitlines()[0]:
        elif 'MESSAGE' in block.splitlines()[0]:
            p = PGPMessage()

        else:
            pytest.skip("not ready for this one")
            assert False

        # load ASCII
        p.parse(block)

        assert str(p) == block


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
        assert p.cipherprefs == []
        assert p.compprefs == []
        assert p.created == datetime.utcfromtimestamp(1402615373)
        assert p.expired is False
        assert p.exportable is True
        assert p.features == []
        assert p.hash2 == b'\xc4\x24'
        assert p.hash_algorithm == HashAlgorithm.SHA512
        assert p.hashprefs == []
        assert p.key_algorithm == PubKeyAlgorithm.RSAEncryptOrSign
        assert p.key_flags == []
        assert p.keyserver == ''
        assert p.keyserverprefs == []
        assert p.magic == "SIGNATURE"
        assert p.notation == {}
        assert p.revocable is True
        assert p.revocation_key is None
        # assert p.revoked is False  # not implemented yet
        assert p.signer == 'FCAE54F74BA27CF7'
        # assert p.target_signature is None  # not implemented yet
        assert p.type == SignatureType.BinaryDocument
        assert p.__bytes__() == bytes(Exportable.ascii_unarmor(rsasigblock)['body'])
        assert str(p) == rsasigblock


# PGPKey specific tests
class TestPGPKey(object):
    def test_load_rsapub(self, rsapubblock):
        p = PGPKey()
        r = p.parse(rsapubblock)

        assert p.fingerprint == "F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36"
        assert p.magic == "PUBLIC KEY BLOCK"
        assert p.parent is None

        assert len(p.userattributes) == 1
        assert len(p.userids) == 1
        assert len(p.signatures) == 0

        # assert p.userids[0].primary
        assert len(p.userattributes[0]._signatures) == 2
        assert len(p.userids[0]._signatures) == 1

        assert p.cipherprefs == [SymmetricKeyAlgorithm.AES256,
                                 SymmetricKeyAlgorithm.AES192,
                                 SymmetricKeyAlgorithm.AES128]
        assert p.compprefs == [CompressionAlgorithm.ZLIB]
        assert p.hashprefs == [HashAlgorithm.SHA256]
        assert p.usageflags == [KeyFlags.Certify]

        # check subkeys
        assert len(p.subkeys) == 2
        skfps = ["7CC4 6C3B E05F 9F9C 9144  CE8B 2A83 4D8E 5918 E886",
                 "00EC FAF5 48AE B655 F861  8193 EEE0 97A0 17B9 79CA"]
        skufs = [[KeyFlags.Sign],
                 [KeyFlags.EncryptStorage, KeyFlags.EncryptCommunications]]
        assert len(set([p] + [sk.parent for sk in p.subkeys.values()])) == 1
        for sk, fp, ufs in zip(p.subkeys.values(), skfps, skufs):
            assert sk.magic == "PUBLIC KEY BLOCK"
            assert sk.ascii_headers == p.ascii_headers
            assert sk.fingerprint == fp
            assert len(sk.signatures) == 1
            assert sk.usageflags == ufs

        assert len(r['keys']) == 0
        assert len(r['orphaned']) == 0

    def test_load_rsapriv(self, rsaprivblock):
        p = PGPKey()
        r = p.parse(rsaprivblock)

        assert p.fingerprint == "F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36"
        assert p.magic == "PRIVATE KEY BLOCK"
        assert p.parent is None

        assert len(p.userattributes) == 0
        assert len(p.userids) == 1

        assert p.cipherprefs == [SymmetricKeyAlgorithm.AES256,
                                 SymmetricKeyAlgorithm.AES192,
                                 SymmetricKeyAlgorithm.AES128,
                                 SymmetricKeyAlgorithm.CAST5,
                                 SymmetricKeyAlgorithm.TripleDES]
        assert p.compprefs == [CompressionAlgorithm.ZLIB,
                               CompressionAlgorithm.BZ2,
                               CompressionAlgorithm.ZIP]
        assert p.usageflags == [KeyFlags.Certify]

        # check subkeys
        assert len(p.subkeys) == 2
        skfps = ["7CC4 6C3B E05F 9F9C 9144  CE8B 2A83 4D8E 5918 E886",
                 "00EC FAF5 48AE B655 F861  8193 EEE0 97A0 17B9 79CA"]
        skufs = [[KeyFlags.Sign],
                 [KeyFlags.EncryptStorage, KeyFlags.EncryptCommunications]]
        assert len(set([p] + [sk.parent for sk in p.subkeys.values()])) == 1
        for sk, fp, ufs in zip(p.subkeys.values(), skfps, skufs):
            assert sk.magic == "PRIVATE KEY BLOCK"
            assert sk.ascii_headers == p.ascii_headers
            assert sk.fingerprint == fp
            assert len(sk.signatures) == 1
            assert sk.usageflags == ufs

        assert len(r['keys']) == 0
        assert len(r['orphaned']) == 0


# PGPMessage specific tests
class TestPGPMessage(object):
    def test_cleartext(self, clearblock):
        p = PGPMessage()
        p.parse(clearblock)

        assert p.type == 'cleartext'
        assert p.is_signed
        assert not p.is_encrypted

        assert p.message == "This is stored, literally\\!\n"

        assert p._halgs == ['SHA1'] or p._halgs == ['SHA1', 'SHA256']
        assert all(isinstance(pkt, PGPSignature) for pkt in p._contents[1:])
        assert len(p.__sig__) in [1, 2]

    def test_literal(self, litblock):
        p = PGPMessage()
        p.parse(litblock)

        assert p.type == 'literal'
        assert not p.is_signed
        assert not p.is_encrypted

        assert p.message == bytearray(b"This is stored, literally\\!\n\n")

        assert len(p.__sig__) == 0

    def test_compressed(self, compblock):
        p = PGPMessage()
        p.parse(compblock)

        assert p.type == 'compressed'
        assert not p.is_signed
        assert not p.is_encrypted

        assert p.message == bytearray(b"This is stored, literally\\!\n\n")

        assert len(p.__sig__) == 0

    def test_onepass(self, onepassblock):
        p = PGPMessage()
        p.parse(onepassblock)

        assert p.type == 'signed'
        assert p.is_signed
        assert not p.is_encrypted

        assert p.__bytes__().startswith(p._contents[0].__bytes__())
        assert p._contents[1].__bytes__() in p.__bytes__()
        assert p.__bytes__().endswith(p._contents[2].__bytes__())

        assert p.message == bytearray(b"This is stored, literally\\!\n\n")

    def test_encrypted(self, encblock):
        p = PGPMessage()
        p.parse(encblock)

        assert p.type == 'encrypted'
        assert p.is_encrypted
