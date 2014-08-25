""" test doing things with keys/signatures/etc
"""
import pytest

from pgpy import PGPKey
from pgpy import PGPSignature

class TestPGPKey(object):
    def test_verify(self, sigf):
        # test verifying signatures in tests/testdata/signatures
        key = PGPKey()
        key.parse(sigf + '.key.asc')
        sig = PGPSignature()
        sig.parse(sigf + '.sig.asc')
        sigv = key.verify(sigf + '.subj', sig)

        assert sigv

    def test_unlock_enckey(self):
        pytest.skip("not implemented yet")

    def test_sign_rsa_bindoc(self):
        # test signing binary documents with RSA
        pytest.skip("not implemented yet")

    def test_sign_dsa_bindoc(self):
        # test signing binary documents with DSA
        pytest.skip("not implemented yet")

    def test_verify_invalid(self):
        pytest.skip("not implemented yet")