# coding=utf-8
""" ensure that we don't crash on surprising messages
"""
import pytest

from pgpy import PGPKey, PGPMessage, PGPSignatures
from pgpy.constants import SecurityIssues
import glob

class TestPGP_Compatibility(object):
    # test compatibility:
    # - Armored object with (non-ASCII) UTF-8 comments
    # - signatures with unknown pubkey algorithms
    # - certs with certifications from unknown algorithms
    # - certs with subkeys with unknown algorithms
    # - certs with ECC subkeys with unknown curves
    # - encrypted messages with surprising parts
    def test_import_unicode_armored_cert(self) -> None:
        k:PGPKey
        (k, _) = PGPKey.from_file('tests/testdata/compatibility/ricarda.pgp')
        assert k.check_soundness() == SecurityIssues.OK

    @pytest.mark.parametrize('sig', glob.glob('*.sig', root_dir='tests/testdata/compatibility'))
    def test_bob_sig_from_multisig(self, sig:str)-> None:
        k:PGPKey
        (k, _) = PGPKey.from_file('tests/testdata/compatibility/bob.pgp')
        msg = 'Hello World :)'
        sigs = PGPSignatures.from_file(f'tests/testdata/compatibility/{sig}')
        verif:Optional[pgpy.SignatureVerification] = None
        for sig in sigs:
            if sig.signer == k.fingerprint.keyid:
                verif = k.verify(msg, sig)
        assert verif is not None

    def test_cert_unknown_algo(self) -> None:
        k:PGPKey
        (k, _) = PGPKey.from_file('tests/testdata/compatibility/bob_with_unknown_alg_certification.pgp')
        assert k.check_soundness() == SecurityIssues.OK

    def test_cert_unknown_subkey_algo(self) -> None:
        k:PGPKey
        (k, _) = PGPKey.from_file('tests/testdata/compatibility/bob_with_unknown_subkey_algorithm.pgp')
        assert k.check_soundness() == SecurityIssues.OK

    @pytest.mark.parametrize('flavor', ['ecdsa', 'eddsa', 'ecdh'])
    def test_cert_unknown_curve(self, flavor:str) -> None:
        k:PGPKey
        (k, _) = PGPKey.from_file(f'tests/testdata/compatibility/bob_with_unknown_{flavor}_curve.pgp')
        assert k.check_soundness() == SecurityIssues.OK

    @pytest.mark.parametrize('msg', glob.glob('*.msg', root_dir='tests/testdata/compatibility'))
    def test_unknown_message(self, msg:str)-> None:
        k:PGPKey
        (k, _) = PGPKey.from_file('tests/testdata/compatibility/bob-key.pgp')
        msg:PGPMessage = PGPMessage.from_file(f'tests/testdata/compatibility/{msg}')
        cleartext:PGPMessage = k.decrypt(msg)
        assert not cleartext.is_encrypted
        assert cleartext.message.startswith(b'Encrypted')
