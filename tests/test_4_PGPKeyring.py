""" test the functionality of PGPKeyring
"""
from pgpy.pgp import PGPKeyring
from pgpy.types import Fingerprint

class TestPGPKeyring(object):
    def test_load(self, ascrings):
        kr = PGPKeyring()
        keys = kr.load(ascrings)

        # keys
        assert all([isinstance(k, Fingerprint) for k in keys])

        # __len__
        assert len(keys) == len(kr)
        assert len(keys) == 12

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
