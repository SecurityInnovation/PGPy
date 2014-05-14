import itertools
import os
from distutils.version import LooseVersion
from subprocess import check_output, STDOUT

import pytest

import pgpy
from pgpy.pgpdump import PGPDumpFormat
from pgpy.errors import PGPError, PGPKeyDecryptionError

from conftest import TestFiles
from conftest import openssl_ver
from conftest import gpg_getfingerprint

def pytest_generate_tests(metafunc):
    args = {}
    ids = []

    if 'keyring' in metafunc.fixturenames:
        args['keyring'] = itertools.repeat(pgpy.PGPKeyring(["tests/testdata/testkeys.gpg",
                                                            "tests/testdata/testkeys.sec.gpg"]))
    # if 'key' in metafunc.fixturenames:
    #     args['key'] = TestFiles.keys
    #     ids = TestFiles.ids(TestFiles.keys)

    if 'keysel' in metafunc.fixturenames:
        fp_rsa1024 = gpg_getfingerprint('TestRSA-1024')
        args['keysel'] = [
            fp_rsa1024[-8:],
            fp_rsa1024[-16:],
            fp_rsa1024,
            ' '.join([ fp_rsa1024[i:i+4] if i != 16 else fp_rsa1024[i:i+4] + ' ' for i in range(0, 40, 4)])
        ]

        ids = ["half-key id", "key id", "fp-no-spaces", "fingerprint"]

    if 'keyid' in metafunc.fixturenames:
        args['keyid'] = [ gpg_getfingerprint('-'.join(list(k))) for k in
                          itertools.product(['TestDSA', 'TestRSA'],
                                            ['1024', '2048', '3072', '4096', 'EncCAST5-1024'])
                        ]

        ids = [ '-'.join(list(k))
                for k in itertools.product(['dsa', 'rsa'],
                                           ['1024', '2048', '3072', '4096', 'cast5-1024']) ]

    if 'sigf' in metafunc.fixturenames:
        args['sigf'] = TestFiles.signatures
        args['sigsub'] = TestFiles.sigsubjects
        ids = TestFiles.ids(TestFiles.signatures)

    metafunc.parametrize(', '.join(args.keys()),
                         list(zip(*args.values())) if len(args.keys()) > 1 else
                         list(*args.values()) if not all(isinstance(x, itertools.repeat) for x in args.values())
                         else [next(list(args.values())[0])],
                         ids=ids)


class TestPGPKeyring(object):
    def test_pgpdump(self, keyring, pgpdump):
        pko = '\n'.join([ '\n'.join(PGPDumpFormat(kp.pubkey).out) for kp in keyring.keys if kp.pubkey is not None]) + '\n'
        sko = '\n'.join([ '\n'.join(PGPDumpFormat(kp.privkey).out) for kp in keyring.keys if kp.privkey is not None]) + '\n'

        assert pko == pgpdump('testkeys.gpg')
        assert sko == pgpdump('testkeys.sec.gpg')

    def test_key_selection(self, keyring, keysel):
        with keyring.key(keysel):
            assert keyring.using == gpg_getfingerprint('TestRSA-1024').replace(' ', '')

    def test_sign(self, request, keyring, keyid, gpg_verify):
        # is this likely to fail?
        if openssl_ver < LooseVersion('1.0.0') and request.node._genid in ['dsa-1024', 'dsa-cast5-1024']:
            pytest.xfail("cryptography + OpenSSL " + str(openssl_ver) + " does not sign correctly with 1024-bit DSA keys")

        with keyring.key(keyid):
            # is this an encrypted private key?
            if keyring.selected.privkey.encrypted:
                # first, make sure an exception is raised if we try to sign with it before decrypting
                with pytest.raises(PGPError):
                    keyring.sign("tests/testdata/unsigned_message")

                # now try with the wrong password
                with pytest.raises(PGPKeyDecryptionError):
                    keyring.unlock("TheWrongPassword")

                # and finally, unlock with the correct password
                keyring.unlock("QwertyUiop")

            # now actually sign
            sig = keyring.sign("tests/testdata/unsigned_message")

        # write out to a file and test with gpg, then remove the file
        sig.path = "tests/testdata/unsigned_message.{refid}.asc".format(refid=request.node._genid)
        sig.write()

        assert 'Good signature from' in gpg_verify('unsigned_message', sig.path.split('/')[-1])

        # and finally, clean up after ourselves
        os.remove(sig.path)

    def test_verify(self, keyring, sigf, sigsub):
        # is this likely to fail?
        if openssl_ver < LooseVersion('1.0.0') and 'DSA' in sigf and int(sigf[-8:-4]) > 1024:
            pytest.xfail("OpenSSL " + str(openssl_ver) + "cannot verify signatures from DSA p > 1024 bits")

        with keyring.key():
            assert keyring.verify('tests/testdata/' + sigsub, 'tests/testdata/' + sigf)

    ##TODO: unmark this when the test is implemented
    @pytest.mark.xfail
    def test_verify_inline(self, keyring):
        with keyring.key():
            keyring.verify("tests/testdata/inline_signed_message.asc", None)