import pytest
from pgpy.key import PGPPublicKey, PGPPrivateKey
from pgpy.packet.pgpdump import PGPDumpFormat

pubkeys = [
    "tests/testdata/pubkeys/TestRSA.key",
    "tests/testdata/pubkeys/TestDSAandElGamal.key",
    "tests/testdata/pubkeys/TestDSA.key",
    "tests/testdata/pubkeys/TestRSASignOnly.key",
    "tests/testdata/pubkeys/ftpmaster_ubuntu_2004.key",
    "tests/testdata/pubkeys/ftpmaster_ubuntu_2012.key",
    "tests/testdata/pubkeys/cdimage_ubuntu_2004.key",
    "tests/testdata/pubkeys/cdimage_ubuntu_2012.key",
    "tests/testdata/pubkeys/TestKeyDecryption-DSA.key",
    "tests/testdata/pubkeys/TestKeyDecryption-DSASignOnly.key",
    "tests/testdata/pubkeys/TestKeyDecryption-RSA.key",
    "tests/testdata/pubkeys/TestKeyDecryption-RSASignOnly.key",
]
keyids_pub = [
    "test-rsa",
    "test-dsa",
    "test-dsa-signony",
    "test-rsa-signonly",
    "ubuntu-2004",
    "ubuntu-2012",
    "cdimage-2004",
    "cdimage-2012",
    "protected-dsa",
    "protected-dsa-signonly",
    "protected-rsa",
    "protected-rsa-signonly",
]
##TODO: need more private key test material
privkeys = [
    "tests/testdata/seckeys/TestRSA.sec.key",
    "tests/testdata/seckeys/TestDSAandElGamal.sec.key",
    "tests/testdata/seckeys/TestDSA.sec.key",
    "tests/testdata/seckeys/TestRSASignOnly.sec.key",
    "tests/testdata/seckeys/TestKeyDecryption-DSA.sec.key",
    "tests/testdata/seckeys/TestKeyDecryption-DSASignOnly.sec.key",
    "tests/testdata/seckeys/TestKeyDecryption-RSA.sec.key",
    "tests/testdata/seckeys/TestKeyDecryption-RSASignOnly.sec.key",
]
keyids_priv = [
    "test-rsa",
    "test-dsa-elgamal",
    "test-dsa",
    "test-rsa-signonly",
    "protected-dsa",
    "protected-dsa-signonly",
    "protected-rsa",
    "protected-rsa-signonly",
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
    def test_parse(self, load_priv, pgpdump):
        k = PGPPrivateKey(load_priv)
        assert '\n'.join(PGPDumpFormat(k).out) + '\n' == pgpdump.decode()

    def test_bytes(self, load_priv):
        k = PGPPrivateKey(load_priv)
        assert k.__bytes__() == k.data