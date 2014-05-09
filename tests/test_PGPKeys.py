import pytest
import subprocess
import re
import cryptography.exceptions

try:
    from tests.conftest import tf, openssl_ver
except:
    from conftest import tf, openssl_ver

from pgpy.pgp import pgpload, PGPKey
from pgpy.pgpdump import PGPDumpFormat
from pgpy.packet.fields import Header

##TODO: change this out for a call to openssl.backend.cipher_supported
##      it might also be a good idea to do that check in the PGPy code,
##      and then just raise an error we can detect (some kidn of UnsupportedError or something)
ciphers = subprocess.check_output(['openssl', 'help'], stderr=subprocess.STDOUT).decode()


@pytest.fixture(params=tf.keys, ids=tf.keyids)
def load_key(request):
    return request.param


@pytest.fixture(params=tf.enckeys, ids=tf.enckeyids)
def load_enc_key(request):
    return request.param

class TestPGPKey:
    def test_parse(self, load_key, pgpdump):
        p = pgpload(load_key)
        k = p[0]

        assert len(p) == 1
        assert type(k) == PGPKey
        assert '\n'.join(PGPDumpFormat(k).out) + '\n' == pgpdump.decode()

    def test_crc24(self, load_key):
        k = pgpload(load_key)[0]
        k.crc == k.crc24()

    def test_keyid(self, load_key):
        k = pgpload(load_key)[0]
        spkt = [pkt.unhashed_subpackets for pkt in k.packets if pkt.header.tag == Header.Tag.Signature][0]

        assert k.keyid == spkt.issuer.payload.decode()

    def test_fingerprint(self, load_key):
        k = pgpload(load_key)[0]
        kfp = [ k.fingerprint[i:(i + 4)] for i in range(0, len(k.fingerprint), 4)]
        kfp[4] += ' '
        kfp = ' '.join(kfp)
        fp = subprocess.check_output(['gpg',
                                      '--no-default-keyring',
                                      '--keyring', 'tests/testdata/testkeys.gpg',
                                      '--secret-keyring', 'tests/testdata/testkeys.sec.gpg',
                                      '--fingerprint', k.keyid])

        assert kfp == re.search(r'Key fingerprint = ([0-9A-F ]*)', fp.decode()).group(1)

    def test_str(self, load_key):
        k = pgpload(load_key)[0]

        assert str(k) == k.bytes.decode()

    def test_bytes(self, load_key):
        k = pgpload(load_key)[0]

        assert k.__bytes__() == k.data

    def test_decrypt_keymaterial(self, load_enc_key):
        k = pgpload(load_enc_key)[0]

        try:
            k.decrypt_keymaterial("QwertyUiop")

        except cryptography.exceptions.UnsupportedAlgorithm as e:
            pytest.xfail("OpenSSL not compiled with support for this symmetric cipher in CFB mode")
            raise

        except NotImplementedError:
            if load_enc_key == 'tests/testdata/seckeys/TestRSA-EncTWOFISH-1024.sec.key':
                pytest.xfail("OpenSSL does not support Twofish at all")
                raise