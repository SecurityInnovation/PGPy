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
    # all of the functions in TestPGPKeyring use this one
    krarg = 'keyring'
    krargval = [pgpy.PGPKeyring(["tests/testdata/testkeys.gpg", "tests/testdata/testkeys.sec.gpg"]),]
    ids = []

    if 'keysel' in metafunc.fixturenames:
        args = krarg + ', keysel'
        fp_rsa1024 = gpg_getfingerprint('TestRSA-1024')
        a1 = krargval * 4
        a2 = [fp_rsa1024[-8:],
              fp_rsa1024[-16:],
              fp_rsa1024,
              ' '.join([ fp_rsa1024[i:i+4] if i != 16 else fp_rsa1024[i:i+4] + ' ' for i in range(0, 40, 4)])]
        argval = list(zip(a1, a2))
        ids = ["half-key id", "key id", "fp-no-spaces", "fingerprint"]

    elif 'keyid' in metafunc.fixturenames:
        args = krarg + ', keyid'
        a2 = [ gpg_getfingerprint('-'.join(list(k))) for k in
               itertools.product(['TestDSA', 'TestRSA'],
                                 ['1024', '2048', '3072', '4096', 'EncCAST5-1024']) ]
        a1 = krargval * len(a2)

        argval = list(zip(a1, a2))
        ids = [ '-'.join(list(k))
                for k in itertools.product(['dsa', 'rsa'],
                                           ['1024', '2048', '3072', '4096', 'cast5-1024']) ]

    elif 'sigf' in metafunc.fixturenames:
        args = krarg + ', sigf, sigsub'
        a1 = krargval * len(TestFiles.signatures)
        a2 = TestFiles.signatures
        a3 = TestFiles.sigsubjects
        argval = list(zip(a1, a2, a3))
        ids = TestFiles.ids(TestFiles.signatures)

    else:
        args = krarg
        argval = krargval

    metafunc.parametrize(args, argval, ids=ids)


class TestPGPKeyring:
    def test_load(self, keyring, pgpdump):
        assert '\n'.join(PGPDumpFormat(keyring).out) + '\n' == ''.join([pgpdump("testkeys.gpg"),
                                                                        pgpdump("testkeys.sec.gpg")])

    def test_magic(self, keyring):
        for key in keyring.keys:
            assert key.type
            if key.secret:
                assert "PRIVATE KEY BLOCK" in str(key)
            else:
                assert "PUBLIC KEY BLOCK" in str(key)

    ##TODO: test keyring contents against ascii armored key contents
    # def test_load2(self, load_key, load_akey):
    #     pass

    ##TODO: this doesn't work right
    # def test_bytes(self, keyring):
    #     fb = b''.join([open(f, 'rb').read() for f in keyring]) if type(keyring) is list else open(load_key, 'rb').read()
    #
    #     assert keyring.__bytes__() == fb

    ##TODO: test str
    # def test_str(self, load_key):
    #     pass

    def test_key_selection(self, keyring, keysel):
        with keyring.key(keysel):
            assert keyring.using == gpg_getfingerprint('TestRSA-1024').replace(' ', '')[-16:]

    def test_sign(self, request, keyring, keyid, gpg_verify):
        # is this likely to fail?
        if openssl_ver < LooseVersion('1.0.0') and request.node._genid in ['dsa-1024', 'dsa-cast5-1024']:
            pytest.xfail("cryptography + OpenSSL " + str(openssl_ver) + " does not sign correctly with 1024-bit DSA keys")

        with keyring.key(keyid):
            # is this an encrypted private key?
            if keyring.selected_privkey.encrypted:
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