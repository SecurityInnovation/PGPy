""" explicitly test error scenarios
"""
import pytest

import glob

from pgpy import PGPKey
from pgpy import PGPKeyring
from pgpy import PGPMessage
from pgpy import PGPSignature
from pgpy import PGPUID

from pgpy.types import Fingerprint
from pgpy.types import SignatureVerification

from pgpy.constants import EllipticCurveOID
from pgpy.constants import HashAlgorithm
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm

from pgpy.errors import PGPDecryptionError
from pgpy.errors import PGPEncryptionError
from pgpy.errors import PGPError
from pgpy.errors import PGPInsecureCipher


def _read(f, mode='r'):
    with open(f, mode) as ff:
        return ff.read()


@pytest.fixture(scope='module')
def rsa_sec():
    return PGPKey.from_file('tests/testdata/keys/rsa.1.sec.asc')[0]


@pytest.fixture(scope='module')
def rsa_enc():
    return PGPKey.from_file('tests/testdata/keys/rsa.1.enc.asc')[0]


@pytest.fixture(scope='module')
def rsa_pub():
    return PGPKey.from_file('tests/testdata/keys/rsa.1.pub.asc')[0]


@pytest.fixture(scope='module')
def targette_sec():
    return PGPKey.from_file('tests/testdata/keys/targette.sec.rsa.asc')[0]


key_algs = [ pka for pka in PubKeyAlgorithm if pka.can_gen and not pka.deprecated ]
key_algs_unim = [ pka for pka in PubKeyAlgorithm if not pka.can_gen and not pka.deprecated]


class TestPGPKey(object):
    params = {
        'key_alg': key_algs,
        'key_alg_unim': key_algs_unim,
    }
    ids = {
        'test_new_key_invalid_size':      [ str(ka).split('.')[-1] for ka in key_algs ],
        'test_new_key_unimplemented_alg': [ str(ka).split('.')[-1] for ka in key_algs_unim ],
    }
    key_badsize = {
        PubKeyAlgorithm.RSAEncryptOrSign: 256,
        PubKeyAlgorithm.DSA: 512,
        PubKeyAlgorithm.ECDSA: 1,
    }

    def test_unlock_pubkey(self, rsa_pub, recwarn):
        with rsa_pub.unlock("QwertyUiop") as _unlocked:
            assert _unlocked is rsa_pub

        w = recwarn.pop(UserWarning)
        assert str(w.message) == "Public keys cannot be passphrase-protected"
        assert w.filename == __file__

    def test_unlock_not_protected(self, rsa_sec, recwarn):
        with rsa_sec.unlock("QwertyUiop") as _unlocked:
            assert _unlocked is rsa_sec

        w = recwarn.pop(UserWarning)
        assert str(w.message) == "This key is not protected with a passphrase"
        assert w.filename == __file__

    def test_unlock_wrong_passphrase(self, rsa_enc):
        with pytest.raises(PGPDecryptionError):
            with rsa_enc.unlock('ClearlyTheWrongPassword'):
                pass

    def test_sign_protected_key(self, rsa_enc):
        with pytest.raises(PGPError):
            rsa_enc.sign("asdf")

    def test_verify_wrongkey(self, rsa_pub):
        wrongkey, _ = PGPKey.from_file('tests/testdata/signatures/aptapproval-test.key.asc')
        sig = PGPSignature.from_file('tests/testdata/signatures/debian-sid.sig.asc')

        with pytest.raises(PGPError):
            wrongkey.verify(_read('tests/testdata/signatures/debian-sid.subj'), sig)

    def test_decrypt_unencrypted_message(self, rsa_sec, recwarn):
        lit = PGPMessage.new('tests/testdata/lit', file=True)
        rsa_sec.decrypt(lit)

        w = recwarn.pop(UserWarning)
        assert str(w.message) == "This message is not encrypted"
        assert w.filename == __file__

    def test_decrypt_wrongkey(self, targette_sec):
        msg = PGPMessage.from_file('tests/testdata/messages/message.rsa.cast5.asc')
        with pytest.raises(PGPError):
            targette_sec.decrypt(msg)

    def test_add_valueerror(self, rsa_sec):
        with pytest.raises(TypeError):
            rsa_sec += 12

    def test_contains_valueerror(self, rsa_sec):
        with pytest.raises(TypeError):
            12 in rsa_sec

    def test_fail_del_uid(self, rsa_sec):
        with pytest.raises(KeyError):
            rsa_sec.del_uid("ASDFDSGSAJGKSAJG")

    def test_encrypt_bad_cipher(self, rsa_pub, recwarn):
        rsa_pub.subkeys['EEE097A017B979CA'].encrypt(PGPMessage.new('asdf'),
                                                    cipher=SymmetricKeyAlgorithm.CAST5)

        w = recwarn.pop(UserWarning)
        assert str(w.message) == "Selected symmetric algorithm not in key preferences"
        assert w.filename == __file__

        w = recwarn.pop(UserWarning)
        assert str(w.message) == "Selected compression algorithm not in key preferences"
        assert w.filename == __file__

    def test_sign_bad_prefs(self, rsa_sec, recwarn):
        rsa_sec.subkeys['2A834D8E5918E886'].sign(PGPMessage.new('asdf'), hash=HashAlgorithm.RIPEMD160)

        w = recwarn.pop(UserWarning)
        assert str(w.message) == "Selected hash algorithm not in key preferences"
        assert w.filename == __file__

    def test_verify_typeerror(self, rsa_sec):
        with pytest.raises(TypeError):
            rsa_sec.verify(12)

        with pytest.raises(TypeError):
            rsa_sec.verify("asdf", signature=12)

    def test_verify_nosigs(self, rsa_sec):
        msg = PGPMessage.new('tests/testdata/lit')
        with pytest.raises(PGPError):
            rsa_sec.verify(msg)

    def test_verify_invalid(self, rsa_sec):
        sig = rsa_sec.sign("Text 1")
        assert not rsa_sec.verify("Text 2", sig)

    def test_parse_wrong_magic(self):
        keytext = _read('tests/testdata/keys/rsa.1.sec.asc').replace('KEY', 'EKY')
        key = PGPKey()
        with pytest.raises(ValueError):
            key.parse(keytext)

    def test_parse_wrong_crc24(self, recwarn):
        keytext = _read('tests/testdata/keys/rsa.1.sec.asc').splitlines()
        keytext[-2] = "=abcd"
        keytext = '\n'.join(keytext)
        key = PGPKey()
        key.parse(keytext)

        w = recwarn.pop(UserWarning)
        assert str(w.message) == "Incorrect crc24"
        assert w.filename == __file__

    def test_empty_key_action(self):
        key = PGPKey()

        with pytest.raises(PGPError):
            key.sign('asdf')

    def test_new_key_no_uid_action(self):
        key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)

        with pytest.raises(PGPError):
            key.sign('asdf')

    def test_new_key_invalid_size(self, key_alg):
        with pytest.raises(ValueError):
            PGPKey.new(key_alg, self.key_badsize[key_alg])

    def test_new_key_unimplemented_alg(self, key_alg_unim):
        with pytest.raises(NotImplementedError):
            PGPKey.new(key_alg_unim, 512)


class TestPGPKeyring(object):
    kr = PGPKeyring(_read('tests/testdata/pubtest.asc'))

    def test_key_keyerror(self):
        with pytest.raises(KeyError):
            with self.kr.key('DEADBEA7CAFED00D'):
                pass


class TestPGPMessage(object):
    def test_decrypt_unsupported_algorithm(self):
        msg = PGPMessage.from_file('tests/testdata/message.enc.twofish.asc')
        with pytest.raises(PGPDecryptionError):
            msg.decrypt("QwertyUiop")

    def test_decrypt_wrongpass(self):
        msg = PGPMessage.from_file(next(f for f in glob.glob('tests/testdata/messages/message*.pass*.asc')))
        with pytest.raises(PGPDecryptionError):
            msg.decrypt("TheWrongPassword")

    def test_decrypt_unencrypted(self):
        msg = PGPMessage.from_file('tests/testdata/messages/message.signed.asc')
        with pytest.raises(PGPError):
            msg.decrypt("Password")

    def test_encrypt_unsupported_algorithm(self):
        lit = PGPMessage.new('tests/testdata/lit')
        with pytest.raises(PGPEncryptionError):
            lit.encrypt("QwertyUiop", cipher=SymmetricKeyAlgorithm.Twofish256)

    def test_encrypt_insecure_cipher(self):
        msg = PGPMessage.new('asdf')
        with pytest.raises(PGPInsecureCipher):
            msg.encrypt('QwertyUiop', cipher=SymmetricKeyAlgorithm.IDEA)

    def test_encrypt_sessionkey_wrongtype(self):
        msg = PGPMessage.new('asdf')
        with pytest.raises(TypeError):
            msg.encrypt('asdf', sessionkey=bytearray(b'asdf1234asdf1234'), cipher=SymmetricKeyAlgorithm.AES128)

    def test_parse_wrong_magic(self):
        msgtext = _read('tests/testdata/messages/message.signed.asc').replace('MESSAGE', 'EMSSAGE')
        msg = PGPMessage()
        with pytest.raises(ValueError):
            msg.parse(msgtext)


class TestPGPSignature(object):
    def test_add_typeerror(self):
        with pytest.raises(TypeError):
            PGPSignature() + 12

    def test_parse_wrong_magic(self):
        sigtext = _read('tests/testdata/blocks/signature.expired.asc').replace('SIGNATURE', 'SIGANTURE')
        sig = PGPSignature()
        with pytest.raises(ValueError):
            sig.parse(sigtext)

    def test_parse_wrong_contents(self):
        notsigtext = _read('tests/testdata/blocks/message.compressed.asc').replace('MESSAGE', 'SIGNATURE')
        sig = PGPSignature()
        with pytest.raises(ValueError):
            sig.parse(notsigtext)


class TestPGPUID(object):
    def test_add_typeerror(self):
        u = PGPUID.new("Asdf Qwert")
        with pytest.raises(TypeError):
            u += 12


class TestSignatureVerification(object):
    def test_and_typeerror(self):
        with pytest.raises(TypeError):
            sv = SignatureVerification() & 12


class TestFingerprint(object):
    def test_bad_input(self):
        with pytest.raises(ValueError):
            Fingerprint("ABCDEFG")

        with pytest.raises(ValueError):
            Fingerprint("ABCD EFGH IJKL MNOP QRST  UVWX YZ01 2345 6789 AABB")
