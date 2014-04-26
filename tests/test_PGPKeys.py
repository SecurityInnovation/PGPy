import pytest
from pgpy.key import PGPPublicKey, PGPPrivateKey
from pgpy.packet.pgpdump import PGPDumpFormat

pubkeys = [
    "tests/testdata/TestRSA.key",
    "tests/testdata/TestDSAandElGamal.key",
    "tests/testdata/TestDSA.key",
    "tests/testdata/TestRSASignOnly.key",
    "tests/testdata/TestProtected.key",
    "tests/testdata/ftpmaster_ubuntu_2004.key",
    "tests/testdata/ftpmaster_ubuntu_2012.key",
    "tests/testdata/cdimage_ubuntu_2004.key",
    "tests/testdata/cdimage_ubuntu_2012.key",
]
keyids_pub = [
    "test-rsa",
    "test-dsa-elgamal",
    "test-dsa",
    "test-rsa-signonly",
    "test-protected",
    "ubuntu-2004",
    "ubuntu-2012",
    "cdimage-2004",
    "cdimage-2012",
]
##TODO: need more private key test material
privkeys = [
    "tests/testdata/TestRSA.sec.key",
    "tests/testdata/TestDSAandElGamal.sec.key",
    "tests/testdata/TestDSA.sec.key",
    "tests/testdata/TestRSASignOnly.sec.key",
    "tests/testdata/TestProtected.sec.key",
]
keyids_priv = [
    "test-rsa",
    "test-dsa-elgamal",
    "test-dsa",
    "test-rsa-signonly",
    "test-protected",
]
@pytest.fixture(params=pubkeys, ids=keyids_pub)
def load_pub(request):
    return request.param

@pytest.fixture(params=privkeys, ids=keyids_priv)
def load_priv(request):
    return request.param


class TestPGPPublicKey:
    def test_parse(self, load_pub, pgpdump):
        k = PGPPublicKey(load_pub)
        assert '\n'.join(PGPDumpFormat(k).out) + '\n' == pgpdump.decode()

    def test_bytes(self, load_pub):
        k = PGPPublicKey(load_pub)
        assert k.__bytes__() == k.data


class TestPGPPrivateKey:
    def test_parse(self, load_priv):
        k = PGPPrivateKey(load_priv)
        assert '\n'.join(PGPDumpFormat(k).out) + '\n' == pgpdump.decode()

    def test_bytes(self, load_priv):
        k = PGPPrivateKey(load_priv)
        assert k.__bytes__() == k.data