import pytest
import os

import pgpy
from pgpy.pgpdump import PGPDumpFormat
from pgpy.errors import PGPError

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

    def test_bytes(self, load_key):
        k = pgpy.PGPKeyring(load_key)
        fb = b''.join([open(f, 'rb').read() for f in load_key]) if type(load_key) is list else open(load_key, 'rb').read()

        assert k.__bytes__() == fb

    ##TODO: test bytes
    # def test_str(self, load_key):
    #     pass

    @pytest.mark.parametrize("sigf, sigsub",
                             [
                                 pytest.mark.xfail(
                                     ("tests/testdata/ubuntu-precise/Release.gpg", "tests/testdata/ubuntu-precise/Release")
                                 ),
                                 ("tests/testdata/debian-sid/Release.gpg", "tests/testdata/debian-sid/Release"),
                                 ("tests/testdata/aa-testing/Release.gpg", "tests/testdata/aa-testing/Release"),
                             ], ids=[
                                 "local-ubuntu",
                                 "local-debian",
                                 "local-aa-testing",
                             ])
    def test_verify(self, sigf, sigsub):
        k = pgpy.PGPKeyring(["tests/testdata/testkeys.gpg", "tests/testdata/testkeys.sec.gpg"])

        with k.key():
            assert k.verify(sigsub, sigf)