""" test the functionality of PGPKeyring
"""
import pytest

from pgpy import PGPKeyring
from pgpy import PGPMessage
from pgpy import PGPSignature
from pgpy.types import Fingerprint


class TestPGPKeyring(object):
    def test_load(self, ascrings):
        kr = PGPKeyring()
        keys = kr.load(ascrings)

        # keys
        assert all([isinstance(k, Fingerprint) for k in keys])

        # __len__
        assert len(keys) == 6
        assert len(kr) == 12

        # __contains__
        # RSA von TestKey
        selectors = ["F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36", "37473B3758C44F36", "58C44F36",
                     "RSA von TestKey", "rsa@test.key"]
        for selector in selectors:
            assert selector in kr

        # DSA von TestKey
        selectors = ["EBC8 8A94 ACB1 10F1 BE3F E3C1 2B47 4BB0 2084 C712", "2B474BB02084C712", "2084C712",
                     "DSA von TestKey", "dsa@test.key"]
        for selector in selectors:
            assert selector in kr

        # fingerprints filtering
        # we have 6 complete keys
        assert len(kr.fingerprints()) == 6
        # 6 public halves, 6 private halves
        assert len(kr.fingerprints(keyhalf='public')) == 6
        assert len(kr.fingerprints(keyhalf='private')) == 6
        # we have 2 primary keys; 2 public and 2 private
        assert len(kr.fingerprints(keytype='primary')) == 2
        assert len(kr.fingerprints(keytype='primary', keyhalf='public')) == 2
        assert len(kr.fingerprints(keytype='primary', keyhalf='private')) == 2
        # and the other 4; 4 public and 4 private
        assert len(kr.fingerprints(keytype='sub')) == 4
        assert len(kr.fingerprints(keytype='sub', keyhalf='public')) == 4
        assert len(kr.fingerprints(keytype='sub', keyhalf='private')) == 4

        # now test sorting:
        rvt = kr._get_keys("RSA von TestKey")
        assert len(rvt) == 2
        assert not rvt[0].is_public
        assert rvt[1].is_public

    def test_select_fingerprint(self, ascrings):
        kr = PGPKeyring(ascrings)

        with kr.key("F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with kr.key("EBC8 8A94 ACB1 10F1 BE3F E3C1 2B47 4BB0 2084 C712") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_keyid(self, ascrings):
        kr = PGPKeyring(ascrings)

        with kr.key("37473B3758C44F36") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with kr.key("2B474BB02084C712") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_shortid(self, ascrings):
        kr = PGPKeyring(ascrings)

        with kr.key("58C44F36") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with kr.key("2084C712") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_name(self, ascrings):
        kr = PGPKeyring(ascrings)

        with kr.key("RSA von TestKey") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with kr.key("DSA von TestKey") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_comment(self, ascrings):
        kr = PGPKeyring(ascrings)

        with kr.key("2048-bit RSA") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with kr.key("2048-bit DSA") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_email(self, ascrings):
        kr = PGPKeyring(ascrings)

        with kr.key("rsa@test.key") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with kr.key("dsa@test.key") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_pgpsignature(self):
        kr = PGPKeyring('tests/testdata/signatures/debian-sid.key.asc')
        sig = PGPSignature()
        sig.parse('tests/testdata/signatures/debian-sid.sig.asc')

        with kr.key(sig) as sigkey:
            assert sigkey.fingerprint.keyid == sig.signer

    def test_select_pgpmessage(self, ascrings):
        kr = PGPKeyring(ascrings)

        m1 = PGPMessage()
        m1.parse('tests/testdata/messages/message.rsa.enc.cast5.asc')
        m2 = PGPMessage()
        m2.parse('tests/testdata/messages/message.dsa.enc.cast5.asc')
        m3 = PGPMessage()
        m3.parse('tests/testdata/blocks/message.signed.asc')

        with kr.key(m1) as rsakey:
            assert rsakey.fingerprint == "00EC FAF5 48AE B655 F861  8193 EEE0 97A0 17B9 79CA"
            assert rsakey.parent.fingerprint == "F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36"

        with kr.key(m2) as dsakey:
            assert dsakey.fingerprint == "BD47 DA72 72BC 2A74 DF9E  B8F5 1FD6 D5D4 DA01 70C4"
            assert dsakey.parent.fingerprint == "EBC8 8A94 ACB1 10F1 BE3F E3C1 2B47 4BB0 2084 C712"

        with kr.key(m3) as rsakey:
            assert rsakey.fingerprint == "7CC4 6C3B E05F 9F9C 9144  CE8B 2A83 4D8E 5918 E886"
            assert rsakey.parent.fingerprint == "F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36"
