""" test doing things with keys/signatures/etc
"""
import pytest

import os
import warnings

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy import PGPSignature

class TestPGPKey(object):
    def test_unlock_enckey(self):
        pytest.skip("not implemented yet")

    def test_verify_detach(self, sigf):
        # test verifying signatures in tests/testdata/signatures
        key = PGPKey()
        key.parse(sigf + '.key.asc')
        sig = PGPSignature()
        sig.parse(sigf + '.sig.asc')
        sigv = key.verify(sigf + '.subj', sig)

        assert sigv

    def test_verify_cleartext(self):
        pytest.skip("not implemented yet")

    def test_verify_message(self):
        pytest.skip("not implemented yet")

    def test_verify_wrongkey(self):
        # test verifying with the wrong key
        pytest.skip("not implemented yet")

    def test_verify_invalid(self):
        # test verifying an invalid signature
        pytest.skip("not implemented yet")

    def test_sign_rsa_bindoc(self, rsakey, gpg_verify):
        # test signing binary documents with RSA
        key = PGPKey()
        key.parse(rsakey)
        sig = key.sign('tests/testdata/lit')

        with open('tests/testdata/lit.sig', 'w') as sigf:
            sigf.write(str(sig))

        # verify with PGPy
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert key.verify('tests/testdata/lit', sig)

        # verify with GPG
        assert 'Good signature from' in gpg_verify('./lit', './lit.sig')

        os.remove('tests/testdata/lit.sig')

    def test_sign_dsa_bindoc(self, dsakey, gpg_verify):
        # test signing binary documents with DSA
        key = PGPKey()
        key.parse(dsakey)
        sig = key.sign('tests/testdata/lit')

        with open('tests/testdata/lit.sig', 'w') as sigf:
            sigf.write(str(sig))

        # verify with PGPy
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert key.verify('tests/testdata/lit', sig)

        # verify with GPG
        assert 'Good signature from' in gpg_verify('./lit', './lit.sig')

        os.remove('tests/testdata/lit.sig')

    def test_decrypt_rsa_message(self, rsamessage):
        key = PGPKey()
        key.parse('tests/testdata/keys/rsa.asc')

        msg = PGPMessage()
        msg.parse(rsamessage)

        decmsg = key.decrypt(msg)

        assert isinstance(decmsg, PGPMessage)
