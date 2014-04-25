import pytest
from pgpy.key import PGPPublicKey, PGPPrivateKey

pubkeys = [
    "tests/testdata/debutils.key",
    # "tests/testdata/debutils.gpg",
    "tests/testdata/ftpmaster_ubuntu_2004.key",
    "tests/testdata/ftpmaster_ubuntu_2012.key",
    "tests/testdata/cdimage_ubuntu_2004.key",
    "tests/testdata/cdimage_ubuntu_2012.key",
    # "tests/testdata/ubuntu_apt_trusted.gpg"
]
keyids_pub = [
    "debutils-ascii",
    # "debutils-keyring",
    "ubuntu-2004",
    "ubuntu-2012",
    "cdimage-2004",
    "cdimage-2012",
    # "apt-keyring",
]
##TODO: need more private key test material
privkeys = [
    "tests/testdata/debutils.key",
    # "tests/testdata/debutils.sec.gpg",
]
keyids_priv = [
    "ascii",
    # "keyring"
]
@pytest.fixture(params=pubkeys, ids=keyids_pub)
def load_pub(request):
    return request.param

@pytest.fixture(params=privkeys, ids=keyids_priv)
def load_priv(request):
    return request.param


class TestPGPPublicKey:
    def test_parse(self, load_pub):
        k = PGPPublicKey(load_pub)

    def test_bytes(self, load_pub):
        k = PGPPublicKey(load_pub)
        assert k.__bytes__() == k.data


class TestPGPPrivateKey:
    def test_parse(self, load_priv):
        k = PGPPrivateKey(load_priv)
        pass

    def test_bytes(self, load_priv):
        k = PGPPrivateKey(load_priv)
        assert k.__bytes__() == k.data
        pass