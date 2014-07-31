import pytest
import re

from pgpy import PGPKey

from pgpy.keys import PGPKeyBlock
from pgpy.errors import PGPOpenSSLCipherNotSupported
from pgpy.pgpdump import PGPDumpFormat
from pgpy.packet.fields.fields import Header

from pgpy.packet.packets import Primary

from conftest import TestFiles

def pytest_generate_tests(metafunc):
    if 'key' in metafunc.fixturenames:
        ids = TestFiles.ids(TestFiles.keys)
        args = 'key'

        argvals = [ key
                    for k in TestFiles.keys
                    for key in PGPKeyBlock.load('tests/testdata/' + k)._keys
                    if isinstance(key, PGPKey) and
                    isinstance(key._keypkt, Primary) ]
        # argvals = [ PGPKey.load('tests/testdata/' + k) for k in TestFiles.keys ]

    if 'enc_key' in metafunc.fixturenames:
        ids = TestFiles.ids(TestFiles.protected_privkeys)
        args = 'enc_key'
        argvals = [ key
                    for k in TestFiles.protected_privkeys
                    for key in PGPKeyBlock.load('tests/testdata/' + k)._keys
                    if isinstance(key, PGPKey) and
                       key.primary ]

    metafunc.parametrize(args, argvals, ids=ids, scope="module")


class TestPGPKeyBlock:
    pass


class TestPGPKey:
    def test_load(self, key):
        assert type(key) == PGPKey

        # key packet
        assert key._keypkt is not None

        # directly related packets
        assert key._userids != []
        assert key._keysigs != []
        ##TODO: not all keys will have _attrs

        # properties
        assert key.primary != key.sub
        assert key.public != key.private
        assert key.magic != "? KEY BLOCK"

        ##TODO: test __bytes__ somehow

    # def test_attrs(self, key):


    # assert '\n'.join(PGPDumpFormat(key).out) + '\n' == pgpdump(key.path)

    # def test_crc24(self, key):
    #     assert key.crc == key.crc24()
    #
    # def test_keyid(self, key):
    #     spkt = [ pkt.unhashed_subpackets for pkt in key.packets if pkt.header.tag == Header.Tag.Signature ][0]
    #
    #     assert key.primarykey.keyid == spkt.issuer.payload.decode()
    #
    # def test_fingerprint(self, key, gpg_fingerprint):
    #     kfp = [ key.primarykey.fingerprint[i:(i + 4)] for i in range(0, len(key.primarykey.fingerprint), 4) ]
    #     kfp[4] += ' '
    #     kfp = ' '.join(kfp)
    #     fp = gpg_fingerprint(key.primarykey.keyid)
    #
    #     assert kfp == re.search(r'Key fingerprint = ([0-9A-F ]*)', fp).group(1)
    #
    # def test_str(self, key):
    #     assert str(key) == key.bytes.decode()
    #
    # def test_bytes(self, key):
    #     assert len(key.__bytes__()) == len(key.data)
    #     assert key.__bytes__() == key.data
    #
    # def test_decrypt_keymaterial(self, enc_key):
    #     try:
    #         enc_key.primarykey.decrypt_keymaterial("QwertyUiop")
    #
    #     except PGPOpenSSLCipherNotSupported:
    #         pytest.xfail("OpenSSL was not compiled with support for this symmetric cipher in CFB mode")
    #         raise