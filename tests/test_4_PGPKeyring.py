""" test the functionality of PGPKeyring
"""
import pytest

from pgpy.pgp import PGPKeyring
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

    def test_select_fingerprint(self):
        pytest.skip("not implemented yet")

    def test_select_keyid(self):
        pytest.skip("not implemented yet")

    def test_select_shortid(self):
        pytest.skip("not implemented yet")

    def test_select_uid(self):
        pytest.skip("not implemented yet")

    def test_select_comment(self):
        pytest.skip("not implemented yet")

    def test_select_email(self):
        pytest.skip("not implemented yet")

    def test_select_pgpsignature(self):
        pytest.skip("not implemented yet")

    def test_select_pgpmessage(self):
        pytest.skip("not implemented yet")
