import itertools
import os
from distutils.version import LooseVersion

import pytest

import pgpy

from pgpy import PGPKey

from pgpy.pgpdump import PGPDumpFormat
from pgpy.errors import PGPError, PGPKeyDecryptionError

from conftest import TestFiles
from conftest import openssl_ver
from conftest import gpg_getfingerprint

def pytest_generate_tests(metafunc):
    args = {}
    ids = []

    if 'keyring' in metafunc.fixturenames:
        args['keyring'] = itertools.repeat(pgpy.PGPKeyring("tests/testdata/testkeys.gpg",
                                                           "tests/testdata/testkeys.sec.gpg"))
    # if 'key' in metafunc.fixturenames:
    #     args['key'] = TestFiles.keys
    #     ids = TestFiles.ids(TestFiles.keys)

    if 'keysel' in metafunc.fixturenames:
        fp_rsa1024 = gpg_getfingerprint('TestRSA-1024')
        args['keysel'] = [
            fp_rsa1024[-8:],
            fp_rsa1024[-16:],
            fp_rsa1024,
            ' '.join([ fp_rsa1024[i:i+4] if i != 16 else fp_rsa1024[i:i+4] + ' ' for i in range(0, 40, 4)]),
            'TestRSA-1024'
        ]

        ids = ["half-key id", "key id", "fp-con", "fp", "username"]

    if 'subkeysel' in metafunc.fixturenames:
        ##TODO: get this from the TestMulti key on disk instead of being hardcoded
        args['subkeysel'] = [
            "8067DD07",
            "1971F7B88067DD07",
            "34712A9D7106DF340EE4E3AA1971F7B88067DD07",
            "3471 2A9D 7106 DF34 0EE4  E3AA 1971 F7B8 8067 DD07",
        ]

        ids = ["subkey half-id", "subkey id", "subkey fp-con", "subkey fp"]

    if 'invkeysel' in metafunc.fixturenames:
        args['invkeysel'] = [ 'DEADBEEF',
                          'CAFEBABE',
                          '1DEE7EFFF55B51578F0E40AB127AB47A',
                          '0'*40,
                          gpg_getfingerprint('TestRSA-1024')[1:] ]
        ids = ['deadbeef', 'cafebabe', '16-byte', '40-null', 'truncated']

    if 'export' in metafunc.fixturenames:
        args['export'] = [ {'pub': True, 'priv': False},
                           {'pub': False, 'priv': True},
                           {'pub': True, 'priv': True},
                           {'pub': False, 'priv': True}]

        ids = ['pub', 'priv', 'both', 'none']

    if 'keyid' in metafunc.fixturenames:
        args['keyid'] = [ gpg_getfingerprint('-'.join(list(k))) for k in
                          itertools.product(['TestDSA', 'TestRSA'],
                                            ['1024', '2048', '3072'])
                         ] + [gpg_getfingerprint('TestRSA-EncCAST5SHA1-1024')]

        ids = [ '-'.join(list(k))
                for k in itertools.product(['dsa', 'rsa'],
                                           ['1024', '2048', '3072'])
               ] + ['rsa-cast5-1024']

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
        pko = '\n'.join([ '\n'.join(PGPDumpFormat(pubkey).out) for pubkey in keyring._keys.__pubkeys__ ]) + '\n'
        sko = '\n'.join([ '\n'.join(PGPDumpFormat(pubkey).out) for pubkey in keyring._keys.__privkeys__ ]) + '\n'

        assert pko == pgpdump('testkeys.gpg')
        assert sko == pgpdump('testkeys.sec.gpg')

    def test_key_selection(self, keyring, keysel):
        with keyring.key(keysel):
            assert keyring.using == gpg_getfingerprint('TestRSA-1024')

    def test_subkey_selection(self, keyring, subkeysel):
        with keyring.key(subkeysel):
            assert keyring.using == "5086 AA4B 3E8F 170C E427  DCE4 B524 74A7 0AAF 5717"

    def test_invalid_selection(self, keyring, invkeysel):
        with pytest.raises(PGPError):
            with keyring.key(invkeysel):
                pass

    def test_export(self, keyring, export):
        with keyring.key(gpg_getfingerprint('TestRSA-1024')):
            k = keyring.export_key(**export)


        if not export['pub']:
            assert k.pubkey is None

        if not export['priv']:
            assert k.privkey is None

        if export['pub']:
            assert k.pubkey is not None
            assert isinstance(k.pubkey, PGPKey)

        if export['priv']:
            assert k.privkey is not None
            assert isinstance(k.privkey, PGPKey)

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