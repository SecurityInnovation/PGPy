import pytest
import os
import sys
from subprocess import check_output, STDOUT

try:
    from tests.conftest import TestFiles
except ImportError:
    from conftest import TestFiles

tf = TestFiles()

import pgpy
from pgpy.pgpdump import PGPDumpFormat
from pgpy.packet.types import PubKeyAlgo
from pgpy.errors import PGPError, PGPKeyDecryptionError

keys = [
    "tests/testdata/testkeys.gpg",
    "tests/testdata/testkeys.sec.gpg",
    ["tests/testdata/testkeys.gpg", "tests/testdata/testkeys.sec.gpg"]
]
keyids = [
    "testkeys",
    "testkeys-sec",
    "testkeys-both",
]


@pytest.fixture(params=keys, ids=keyids)
def load_key(request):
    return request.param

akeys = [
    [ k for k in os.listdir("tests/testdata/pubkeys/") if k[-4:] == ".key" ],
    [ k for k in os.listdir("tests/testdata/seckeys/") if k[-8:] == ".sec.key" ],
]
akeys.append(keys[0] + keys[1])
akeyids = [
    "pubkeys",
    "seckeys",
    "both"
]


@pytest.fixture(params=akeys, ids=akeyids)
def load_akey(request):
    return request.param


class TestPGPKeyring:
    def test_load(self, load_key, pgpdump):
        k = pgpy.PGPKeyring(load_key)

        assert '\n'.join(PGPDumpFormat(k).out) + '\n' == pgpdump.decode()

    ##TODO: test keyring contents against ascii armored key contents
    # def test_load2(self, load_key, load_akey):
    #     pass

    ##TODO: is this test actually useful?
    # @pytest.mark.parametrize("prop", [ k for k, thing in pgpy.PGPKeyring.__dict__.items() if type(thing) is property ])
    # def test_properties(self, prop):
    #     k = pgpy.PGPKeyring(["tests/testdata/testkeys.gpg", "tests/testdata/testkeys.sec.gpg"])
    #
    #     try:
    #         eval("k.{p}".format(p=prop)) is not None
    #
    #     except KeyError:
    #         if prop[:8] != "selected":
    #             pytest.fail("k.{p} raised KeyError".format(p=prop))
    #
    #     except:
    #         e = sys.exc_info()[0]
    #         pytest.fail("k.{p} raised {ex}".format(p=prop, ex=str(e)))

    def test_bytes(self, load_key):
        k = pgpy.PGPKeyring(load_key)
        fb = b''.join([open(f, 'rb').read() for f in load_key]) if type(load_key) is list else open(load_key, 'rb').read()

        assert k.__bytes__() == fb

    ##TODO: test str
    # def test_str(self, load_key):
    #     pass

    ##TODO: don't hardcode this - get the info from the first key alphabetically
    @pytest.mark.parametrize("keyid",
                             ["3F3DDA4C",
                              "642546A53F3DDA4C",
                              "F3E0666247D1D9DA4D6447CA642546A53F3DDA4C",
                              "F3E0 6662 47D1 D9DA 4D64  47CA 6425 46A5 3F3D DA4C"],
                             ids=["half-key id", "key id", "fp-no-spaces", "fingerprint"])
    def test_key_selection(self, keyid):
        k = pgpy.PGPKeyring(["tests/testdata/testkeys.gpg", "tests/testdata/testkeys.sec.gpg"])

        with k.key(keyid):
            assert k.using == "642546A53F3DDA4C"

    ##TODO: better refactor the parametrization of this test
    @pytest.mark.parametrize("keyid",
                             [
                                 "642546A53F3DDA4C", # TestRSA-1024
                                 "5D28BF073325A4E7", # TestRSA-2048
                                 "C2D6BA57AEF0B534", # TestRSA-3072
                                 "D5A7CB4B1E95616E", # TestRSA-4096
                                 "EDE981F5CAFD4E2F", # TestDSA-1024
                                 "58350056D8046712", # TestDSA-2048
                                 "FA35AD25FCAC544C", # TestDSA-3072
                                 "1C5D9C9C8F9BF36E", # TestDSA-4096
                                 "E6DF2EF657E2B327", # TestRSA-EncCAST5-1024
                                 "624D36067A9F2F3B", # TestDSA-EncCAST5-1024
                             ], ids=[
                                'rsa-1024',
                                'rsa-2048',
                                'rsa-3072',
                                'rsa-4096',
                                'dsa-1024',
                                'dsa-2048',
                                'dsa-3072',
                                'dsa-4096',
                                'rsa-cast5-1024',
                                'dsa-cast5-1024',
                             ])
    def test_sign(self, request, keyid):
        k = pgpy.PGPKeyring(["tests/testdata/testkeys.gpg", "tests/testdata/testkeys.sec.gpg"])

        with k.key(keyid):
            # is this an encrypted private key?
            if k.selected_privkey.encrypted:
                # first, make sure an exception is raised if we try to sign with it before decrypting
                with pytest.raises(PGPError):
                    k.sign("tests/testdata/unsigned_message")

                # now try with the wrong password
                with pytest.raises(PGPKeyDecryptionError):
                    k.unlock("TheWrongPassword")

                # and finally, unlock with the correct password
                k.unlock("QwertyUiop")

            # now sign
            try:
                sig = k.sign("tests/testdata/unsigned_message")

            except AssertionError:
                if sys.platform == 'darwin' and request.node._genid in ['dsa-1024', 'dsa-cast5-1024']:
                    # for some reason, signing things with DSA keys with p values of 1024-bits
                    # does not work right with OpenSSL v0.9.8y on OSX.
                    # (see issue #16 - https://github.com/Commod0re/PGPy/issues/16)
                    pytest.xfail("OpenSSL on OSX is janky")
                    raise

        # write out to a file and test with gpg, then remove the file
        sig.path = "tests/testdata/unsigned_message.{refid}.asc".format(refid=request.node._genid)
        sig.write()

        assert b'Good signature from' in \
            check_output(['gpg',
                          '--no-default-keyring',
                          '--keyring', 'tests/testdata/testkeys.gpg',
                          '--secret-keyring', 'tests/testdata/testkeys.sec.gpg',
                          '--trustdb-name', 'tests/testdata/testkeys.trust',
                          '-vv',
                          '--verify', sig.path,
                          'tests/testdata/unsigned_message'], stderr=STDOUT)

        # and finally, clean up after ourselves
        os.remove(sig.path)


    @pytest.mark.parametrize("sigf, sigsub",
                             list(zip(tf.sigs, tf.sigm)), ids=tf.sigids)
    def test_verify_signature(self, sigf, sigsub):
        k = pgpy.PGPKeyring(["tests/testdata/testkeys.gpg", "tests/testdata/testkeys.sec.gpg"])


        with k.key():
            try:
                assert k.verify(sigsub, sigf)

            except AssertionError:
                if 'DSA' in sigf and int(sigf[-8:-4]) > 1024:
                    pytest.xfail("Some versions of OpenSSL can't handle DSA p > 1024 bits")
                raise
