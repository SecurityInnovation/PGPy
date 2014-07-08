import pytest
import re

from pgpy.errors import PGPOpenSSLCipherNotSupported
from pgpy.pgp import pgpload, PGPKey
from pgpy.pgpdump import PGPDumpFormat
from pgpy.packet.fields.fields import Header

from conftest import TestFiles

def pytest_generate_tests(metafunc):
    if 'key' in metafunc.fixturenames:
        ids = TestFiles.ids(TestFiles.keys)
        args = 'key'
        argvals = [ pgpload('tests/testdata/' + k)[0] for k in TestFiles.keys ]

    if 'enc_key' in metafunc.fixturenames:
        ids = TestFiles.ids(TestFiles.protected_privkeys)
        args = 'enc_key'
        argvals = [ pgpload('tests/testdata/' + k)[0] for k in TestFiles.protected_privkeys ]

    metafunc.parametrize(args, argvals, ids=ids, scope="module")


class TestPGPKey:
    def test_parse(self, key, pgpdump):
        assert type(key) == PGPKey
        assert '\n'.join(PGPDumpFormat(key).out) + '\n' == pgpdump(key.path)

    def test_crc24(self, key):
        assert key.crc == key.crc24()

    def test_keyid(self, key):
        spkt = [ pkt.unhashed_subpackets for pkt in key.packets if pkt.header.tag == Header.Tag.Signature ][0]

        assert key.primarykey.keyid == spkt.issuer.payload.decode()

    def test_fingerprint(self, key, gpg_fingerprint):
        kfp = [ key.primarykey.fingerprint[i:(i + 4)] for i in range(0, len(key.primarykey.fingerprint), 4) ]
        kfp[4] += ' '
        kfp = ' '.join(kfp)
        fp = gpg_fingerprint(key.primarykey.keyid)

        assert kfp == re.search(r'Key fingerprint = ([0-9A-F ]*)', fp).group(1)

    def test_str(self, key):
        assert str(key) == key.bytes.decode()

    def test_bytes(self, key):
        assert len(key.__bytes__()) == len(key.data)
        assert key.__bytes__() == key.data

    def test_decrypt_keymaterial(self, enc_key):
        try:
            enc_key.decrypt_keymaterial("QwertyUiop")

        except PGPOpenSSLCipherNotSupported:
            pytest.xfail("OpenSSL was not compiled with support for this symmetric cipher in CFB mode")
            raise