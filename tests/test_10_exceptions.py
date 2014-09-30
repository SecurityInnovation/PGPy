""" explicitly test error scenarios
"""
import pytest

import glob

from pgpy import PGPKey
from pgpy import PGPKeyring
from pgpy import PGPMessage
from pgpy import PGPSignature
from pgpy import PGPUID

from pgpy.constants import SymmetricKeyAlgorithm

from pgpy.errors import PGPDecryptionError
from pgpy.errors import PGPEncryptionError
from pgpy.errors import PGPError


def _pgpkey(f):
    key = PGPKey()
    with open(f, 'r') as ff:
        key.parse(ff.read())
    return key

def _pgpmessage(f):
    msg = PGPMessage()
    with open(f, 'r') as ff:
        msg.parse(ff.read())
    return msg

def _pgpsignature(f):
    sig = PGPSignature()
    with open(f, 'r') as ff:
        sig.parse(ff.read())
    return sig

def _read(f, mode='r'):
    with open(f, mode) as ff:
        return ff.read()


class TestPGPKey(object):
    rsa_1_sec = _pgpkey('tests/testdata/keys/rsa.1.sec.asc')
    rsa_2_sec = _pgpkey('tests/testdata/keys/rsa.2.sec.asc')

    def test_verify_wrongkey(self):
        wrongkey = _pgpkey('tests/testdata/signatures/aptapproval-test.key.asc')
        sig = _pgpsignature('tests/testdata/signatures/debian-sid.sig.asc')

        with pytest.raises(PGPError):
            wrongkey.verify(_read('tests/testdata/signatures/debian-sid.subj'), sig)

    def test_decrypt_unencrypted_message(self, recwarn):
        lit = PGPMessage.new('tests/testdata/lit')
        self.rsa_1_sec.decrypt(lit)

        w = recwarn.pop(UserWarning)
        assert str(w.message) == "This message is not encrypted"
        assert w.filename == __file__

    def test_decrypt_wrongkey(self):
        msg = _pgpmessage('tests/testdata/messages/message.rsa.cast5.asc')
        with pytest.raises(PGPError):
            self.rsa_2_sec.decrypt(msg)

    def test_add_valueerror(self):
        with pytest.raises(TypeError):
            self.rsa_1_sec += 12

    def test_contains_valueerror(self):
        with pytest.raises(TypeError):
            12 in self.rsa_1_sec

    def test_fail_del_uid(self):
        with pytest.raises(PGPError):
            self.rsa_1_sec.del_uid("ASDFDSGSAJGKSAJG")

    def test_verify_typeerror(self):
        with pytest.raises(TypeError):
            self.rsa_1_sec.verify(12)

        with pytest.raises(TypeError):
            self.rsa_1_sec.verify("asdf", signature=12)

    def test_verify_nosigs(self):
        msg = PGPMessage.new('tests/testdata/lit')
        with pytest.raises(PGPError):
            self.rsa_1_sec.verify(msg)

    def test_parse_wrong_magic(self):
        keytext = _read('tests/testdata/keys/rsa.1.sec.asc').replace('KEY', 'EKY')
        key = PGPKey()
        with pytest.raises(ValueError):
            key.parse(keytext)


class TestPGPKeyring(object):
    kr = PGPKeyring(_read('tests/testdata/pubtest.asc'))

    def test_key_keyerror(self):
        with pytest.raises(KeyError):
            with self.kr.key('DEADBEA7CAFED00D'):
                pass


class TestPGPMessage(object):
    def test_decrypt_unsupported_algorithm(self):
        msg = _pgpmessage('tests/testdata/message.enc.twofish.asc')
        with pytest.raises(PGPDecryptionError):
            msg.decrypt("QwertyUiop")

    def test_decrypt_wrongpass(self):
        msg = _pgpmessage(next(f for f in glob.glob('tests/testdata/messages/message*.pass*.asc')))
        with pytest.raises(PGPDecryptionError):
            msg.decrypt("TheWrongPassword")

    def test_decrypt_unencrypted(self):
        msg = _pgpmessage('tests/testdata/messages/message.signed.asc')
        with pytest.raises(PGPError):
            msg.decrypt("Password")

    def test_encrypt_unsupported_algorithm(self):
        lit = PGPMessage.new('tests/testdata/lit')
        with pytest.raises(PGPEncryptionError):
            lit.encrypt("QwertyUiop", cipher=SymmetricKeyAlgorithm.Twofish256)

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
    def test_bad_new(self):
        with pytest.raises(ValueError):
            PGPUID.new()

    def test_add_typeerror(self):
        u = PGPUID.new(name="Asdf Qwert")
        with pytest.raises(TypeError):
            u += 12
