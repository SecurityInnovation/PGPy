import pytest
from pgpy.key import PGPKeyLoader

@pytest.fixture(params=[
                    "tests/testdata/debutils.key",
                    "tests/testdata/debutils.gpg",
                    "tests/testdata/debutils.sec.gpg"
                ],
                ids=[
                    "ascii",
                    "gpg-public",
                    "gpg-private"
                ])
def load_key(request):
    return PGPKeyLoader(request.param)


class TestPGPKeyLoader:
    def test_parse(self, load_key):
        # assert len(load_key.keys) > 0
        pass