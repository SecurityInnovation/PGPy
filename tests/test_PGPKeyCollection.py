import pytest

import pgpy
from pgpy.pgpdump import PGPDumpFormat

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


class TestPGPKeyLoader:
    def test_load(self, load_key, pgpdump):
        with pgpy.PGPKeyCollection(load_key) as k:
            assert '\n'.join(PGPDumpFormat(k).out) + '\n' == pgpdump.decode()

    def test_bytes(self, load_key):
        with pgpy.PGPKeyCollection(load_key) as k:
            fb = b''.join([open(f, 'rb').read() for f in load_key]) if type(load_key) is list else open(load_key, 'rb').read()

            assert k.__bytes__() == fb

    # def test_list_pubkeys(self, load_key):
    #     pass

    # def test_list_privkeys(self, load_key):
    #     pass

    def test_str(self, load_key):
        with pgpy.PGPKeyCollection(load_key) as k:
            pass