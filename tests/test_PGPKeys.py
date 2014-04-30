import pytest
import subprocess
import re

from pgpy.pgp import PGPLoad, PGPKey
from pgpy.pgpdump import PGPDumpFormat
from pgpy.packet.fields import Header

pubkeys = [
    "tests/testdata/pubkeys/TestRSA.key",
    "tests/testdata/pubkeys/TestDSAandElGamal.key",
    "tests/testdata/pubkeys/TestDSA.key",
    "tests/testdata/pubkeys/TestRSASignOnly.key",
    "tests/testdata/pubkeys/ftpmaster_ubuntu_2004.key",
    "tests/testdata/pubkeys/ftpmaster_ubuntu_2012.key",
    "tests/testdata/pubkeys/cdimage_ubuntu_2004.key",
    "tests/testdata/pubkeys/cdimage_ubuntu_2012.key",
    "tests/testdata/pubkeys/debian-sid.key",
    "tests/testdata/pubkeys/aptapproval-test.key",
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
    "debian-sid",
    "aa-test",
    "protected-dsa",
    "protected-dsa-signonly",
    "protected-rsa",
    "protected-rsa-signonly",
]
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
    "sec-test-rsa",
    "sec-test-dsa-elgamal",
    "sec-test-dsa",
    "sec-test-rsa-signonly",
    "sec-protected-dsa",
    "sec-protected-dsa-signonly",
    "sec-protected-rsa",
    "sec-protected-rsa-signonly",
]
@pytest.fixture(params=pubkeys + privkeys, ids=keyids_pub + keyids_priv)
def load_key(request):
    return request.param

class TestPGPKey:
    def test_parse(self, load_key, pgpdump):
        p = PGPLoad(load_key)
        k = p[0]

        assert len(p) == 1
        assert type(k) == PGPKey
        assert '\n'.join(PGPDumpFormat(k).out) + '\n' == pgpdump.decode()

    def test_crc24(self, load_key):
        k = PGPLoad(load_key)[0]
        k.crc == k.crc24()

    def test_keyid(self, load_key):
        k = PGPLoad(load_key)[0]
        spkt = [pkt.unhashed_subpackets for pkt in k.packets if pkt.header.tag == Header.Tag.Signature][0]

        assert k.keyid == spkt.Issuer.payload.decode()

    def test_fingerprint(self, load_key):
        k = PGPLoad(load_key)[0]
        kfp = [ k.fingerprint[i:(i+4)] for i in range(0, len(k.fingerprint), 4)]
        kfp[4] += ' '
        kfp = ' '.join(kfp)
        fp = subprocess.check_output(['gpg',
                                      '--no-default-keyring',
                                      '--keyring', 'tests/testdata/testkeys.gpg',
                                      '--secret-keyring', 'tests/testdata/testkeys.sec.gpg',
                                      '--fingerprint', k.keyid])

        assert kfp == re.search(r'Key fingerprint = ([0-9A-F ]*)', fp.decode()).group(1)

    def test_str(self, load_key):
        k = PGPLoad(load_key)[0]

        assert str(k) == k.bytes.decode()

    @pytest.mark.parametrize("key", [
        "tests/testdata/seckeys/TestKeyDecryption-DSA.sec.key",
        "tests/testdata/seckeys/TestKeyDecryption-DSASignOnly.sec.key",
        "tests/testdata/seckeys/TestKeyDecryption-RSA.sec.key",
        "tests/testdata/seckeys/TestKeyDecryption-RSASignOnly.sec.key",
    ], ids=[
        "sec-protected-dsa",
        "sec-protected-dsa-signonly",
        "sec-protected-rsa",
        "sec-protected-rsa-signonly",
    ])
    def test_decrypt_keymaterial(self, key):
        k = PGPLoad(key)[0]
        k.decrypt_keymaterial("QwertyUiop")

        print(k)

    def test_bytes(self, load_key):
        k = PGPLoad(load_key)[0]

        assert k.__bytes__() == k.data