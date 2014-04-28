import pytest
from pgpy.key import PGPKeyCollection

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
        k = PGPKeyCollection(load_key)


    # def test_bytes(self):
    #     pass