""" test the functionality of PGPKeyring
"""
import glob

from pgpy import PGPKeyring
from pgpy import PGPMessage
from pgpy import PGPSignature
from pgpy.types import Fingerprint


class TestPGPKeyring(object):
    kr = PGPKeyring()

    def test_load(self):
        kc = []
        for kf in glob.glob('tests/testdata/*test.asc') + glob.glob('tests/testdata/signatures/*.key.asc'):
            with open(kf, 'r') as kff:
                kc.append(kff.read())
        keys = self.kr.load(kc)

        # keys
        assert all(isinstance(k, Fingerprint) for k in keys)

        # __len__
        assert len(keys) == 10
        assert len(self.kr) == 16

        # __contains__
        #  RSA von TestKey
        selectors = ["F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36", "37473B3758C44F36", "58C44F36",
                     "RSA von TestKey", "rsa@test.key"]
        for selector in selectors:
            assert selector in self.kr

        #  DSA von TestKey
        selectors = ["EBC8 8A94 ACB1 10F1 BE3F E3C1 2B47 4BB0 2084 C712", "2B474BB02084C712", "2084C712",
                     "DSA von TestKey", "dsa@test.key"]
        for selector in selectors:
            assert selector in self.kr

        # fingerprints filtering
        #  we have 10 keys
        assert len(self.kr.fingerprints()) == 10
        #  10 public halves, 6 private halves
        assert len(self.kr.fingerprints(keyhalf='public')) == 10
        assert len(self.kr.fingerprints(keyhalf='private')) == 6
        #  we have 5 primary keys; 5 public and 2 private
        assert len(self.kr.fingerprints(keytype='primary')) == 5
        assert len(self.kr.fingerprints(keytype='primary', keyhalf='public')) == 5
        assert len(self.kr.fingerprints(keytype='primary', keyhalf='private')) == 2
        #  and the other 5; 5 public and 4 private
        assert len(self.kr.fingerprints(keytype='sub')) == 5
        assert len(self.kr.fingerprints(keytype='sub', keyhalf='public')) == 5
        assert len(self.kr.fingerprints(keytype='sub', keyhalf='private')) == 4

        # now test sorting:
        rvt = self.kr._get_keys("RSA von TestKey")
        assert len(rvt) == 2
        assert not rvt[0].is_public
        assert rvt[1].is_public

    def test_select_fingerprint(self):
        with self.kr.key("F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with self.kr.key("EBC8 8A94 ACB1 10F1 BE3F E3C1 2B47 4BB0 2084 C712") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_keyid(self):
        with self.kr.key("37473B3758C44F36") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with self.kr.key("2B474BB02084C712") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_shortid(self):
        with self.kr.key("58C44F36") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with self.kr.key("2084C712") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_name(self):
        with self.kr.key("RSA von TestKey") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with self.kr.key("DSA von TestKey") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_comment(self):
        with self.kr.key("2048-bit RSA") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with self.kr.key("2048-bit DSA") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_email(self):
        with self.kr.key("rsa@test.key") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with self.kr.key("dsa@test.key") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_pgpsignature(self):
        sig = PGPSignature()
        with open('tests/testdata/signatures/debian-sid.sig.asc', 'r') as sigf:
            sig.parse(sigf.read())

        with self.kr.key(sig) as sigkey:
            assert sigkey.fingerprint.keyid == sig.signer

    def test_select_pgpmessage(self):
        m1 = PGPMessage()
        with open('tests/testdata/messages/message.rsa.cast5.asc', 'r') as m1f:
            m1.parse(m1f.read())

        with self.kr.key(m1) as rsakey:
            assert rsakey.fingerprint == "00EC FAF5 48AE B655 F861  8193 EEE0 97A0 17B9 79CA"
            assert rsakey.parent.fingerprint == "F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36"
