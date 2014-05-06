import pytest
import os
import sys
from subprocess import check_output, STDOUT
from distutils.version import LooseVersion

from cryptography.hazmat.backends import openssl
# mosslv = LooseVersion("1.0.0")
# osslv = LooseVersion(openssl.backend.openssl_version_text().split(' ')[1])

import pgpy
from pgpy.pgpdump import PGPDumpFormat
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

    @pytest.mark.parametrize("prop", [ k for k, thing in pgpy.PGPKeyring.__dict__.items()
                                       if type(thing) is property ])
    def test_properties(self, prop):
        k = pgpy.PGPKeyring(["tests/testdata/testkeys.gpg", "tests/testdata/testkeys.sec.gpg"])

        try:
            eval("k.{p}".format(p=prop)) is not None

        except KeyError:
            if prop[:8] != "selected":
                pytest.fail("k.{p} raised KeyError".format(p=prop))

        except:
            e = sys.exc_info()[0]
            pytest.fail("k.{p} raised {ex}".format(p=prop, ex=str(e)))

    def test_bytes(self, load_key):
        k = pgpy.PGPKeyring(load_key)
        fb = b''.join([open(f, 'rb').read() for f in load_key]) if type(load_key) is list else open(load_key, 'rb').read()

        assert k.__bytes__() == fb

    ##TODO: test str
    # def test_str(self, load_key):
    #     pass

    @pytest.mark.parametrize("keyid",
                             ["9AFBC22F", "6D30F6669AFBC22F",
                              "ADC14E18DAD752BBF78D44226D30F6669AFBC22F",
                              "ADC1 4E18 DAD7 52BB F78D  4422 6D30 F666 9AFB C22F"],
                             ids=["half-key id", "key id", "fp-no-spaces", "fingerprint"])
    def test_key_selection(self, keyid):
        k = pgpy.PGPKeyring(["tests/testdata/testkeys.gpg", "tests/testdata/testkeys.sec.gpg"])

        with k.key(keyid):
            assert k.using == "6D30F6669AFBC22F"

    @pytest.mark.parametrize("keyid",
                             [
                                 "6C368E85",  # TestRSAKey
                                 "AD66AAD5",  # TestKeyDecryption-RSA
                                 "9AFBC22F",  # TestDSAKey
                                 "C511044C",  # TestDSAKey-1024
                                 "FAB79385",  # TestKeyDecryption-DSA
                                 "61AAE186",  # TestKeyDecryption-DSA-1024
                                 "F880CE25",  # TestDSAandElGamalKey
                                 "08866F66",  # TestDSAandElGamal-1024
                             ], ids=[
                                 "rsa",
                                 "enc-rsa",
                                 "dsa",
                                 "dsa-1024",
                                 "enc-dsa",
                                 "enc-dsa-1024",
                                 "enc-dsa-elg",
                                 "enc-dsa-elg-1024",
                             ])
    def test_sign_with_key(self, keyid):
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
            sig = k.sign("tests/testdata/unsigned_message")

        # write out to a file and test with gpg, then remove the file
        sig.path = "tests/testdata/unsigned_message.asc"
        sig.write()

        assert b'Good signature from' in \
            check_output(['gpg',
                          '--no-default-keyring',
                          '--keyring', 'tests/testdata/testkeys.gpg',
                          '--secret-keyring', 'tests/testdata/testkeys.sec.gpg',
                          '-vv',
                          '--verify', 'tests/testdata/unsigned_message.asc',
                          'tests/testdata/unsigned_message'], stderr=STDOUT)
        os.remove('tests/testdata/unsigned_message.asc')

        # finally, verify the signature ourselves to make sure that works
        with k.key():
            sigv = k.verify("tests/testdata/unsigned_message", str(sig))

            # used the same key
            assert sigv.key.keyid[-8:] == keyid
            # signature verified
            assert sigv

    @pytest.mark.parametrize("sigf, sigsub",
                             [
                                 ("tests/testdata/ubuntu-precise/Release.gpg", "tests/testdata/ubuntu-precise/Release"),
                                 ("tests/testdata/debian-sid/Release.gpg", "tests/testdata/debian-sid/Release"),
                                 ("tests/testdata/aa-testing/Release.gpg", "tests/testdata/aa-testing/Release"),
                                 ("tests/testdata/signed_message.asc", "tests/testdata/signed_message"),
                             ], ids=[
                                 "local-ubuntu",
                                 "local-debian",
                                 "local-aa-testing",
                                 "signed_message",
                             ])
    def test_verify_signature(self, sigf, sigsub):
        k = pgpy.PGPKeyring(["tests/testdata/testkeys.gpg", "tests/testdata/testkeys.sec.gpg"])

        with k.key():
            assert k.verify(sigsub, sigf)