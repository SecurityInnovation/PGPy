import pytest
from pgpy.key import PGPKeyCollection

keys = [
    "tests/testdata/debutils.key",
    "tests/testdata/debutils.gpg",
    "tests/testdata/debutils.sec.gpg"
]
keyids = [
    "ascii",
    "gpg-public",
    "gpg-private"
]
@pytest.fixture(params=keys, ids=keyids)
def load_key(request):
    return PGPKeyCollection(request.param)


class TestPGPKeyLoader:
    pass