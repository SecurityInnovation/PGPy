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

from pgpy.constants import HashAlgorithm
from pgpy.constants import SignatureType
from pgpy.constants import SymmetricKeyAlgorithm

from pgpy.errors import PGPDecryptionError
from pgpy.errors import PGPEncryptionError
from pgpy.errors import PGPError
from pgpy.errors import PGPInsecureCipher


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
    rsa_1_pub = _pgpkey('tests/testdata/keys/rsa.1.pub.asc')
    # rsa_2_sec = _pgpkey('tests/testdata/keys/rsa.2.sec.asc')
    # rsa_2_pub = _pgpkey('tests/testdata/keys/rsa.2.pub.asc')

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

    # def test_decrypt_wrongkey(self):
    #     msg = _pgpmessage('tests/testdata/messages/message.rsa.cast5.asc')
    #     with pytest.raises(PGPError):
    #         self.rsa_2_sec.decrypt(msg)

    def test_add_valueerror(self):
        with pytest.raises(TypeError):
            self.rsa_1_sec += 12

    def test_contains_valueerror(self):
        with pytest.raises(TypeError):
            12 in self.rsa_1_sec

    def test_fail_del_uid(self):
        with pytest.raises(PGPError):
            self.rsa_1_sec.del_uid("ASDFDSGSAJGKSAJG")

    # def test_sign_wrong_type(self):
    #     msg = _pgpmessage('tests/testdata/messages/message.rsa.cast5.asc')
    #     ctmsg = _pgpmessage('tests/testdata/messages/cleartext.signed.asc')
    #     uid = PGPUID.new(name="asdf")
    #     sigtypes = {SignatureType.BinaryDocument, SignatureType.CanonicalDocument, SignatureType.Standalone,
    #                 SignatureType.Subkey_Binding, SignatureType.PrimaryKey_Binding, SignatureType.DirectlyOnKey,
    #                 SignatureType.KeyRevocation, SignatureType.SubkeyRevocation, SignatureType.Timestamp,
    #                 SignatureType.ThirdParty_Confirmation} | SignatureType.certifications
    #
    #     # invalid subject/sigtype combinations
    #     invalid_combos = []
    #     invalid_combos += [('asdf', st) for st in sigtypes ^ {SignatureType.BinaryDocument}]
    #     invalid_combos += [(msg, st) for st in sigtypes ^ {SignatureType.BinaryDocument}]
    #     invalid_combos += [(ctmsg, st) for st in sigtypes ^ {SignatureType.CanonicalDocument}]
    #     invalid_combos += [(uid, st) for st in sigtypes ^ SignatureType.certifications]
    #     invalid_combos += [(self.rsa_2_sec, st) for st in sigtypes ^ {SignatureType.DirectlyOnKey,
    #                                                                   SignatureType.PrimaryKey_Binding,
    #                                                                   SignatureType.KeyRevocation}]
    #
    #     for subj, type in invalid_combos:
    #         with pytest.raises(PGPError):
    #             self.rsa_1_sec.sign(subj, sigtype=type)

    def test_sign_bad_prefs(self, recwarn):
        self.rsa_1_pub.subkeys['EEE097A017B979CA'].encrypt(PGPMessage.new('asdf'),
                               cipher=SymmetricKeyAlgorithm.CAST5,
                               hash=HashAlgorithm.SHA1)

        w = recwarn.pop(UserWarning)
        assert str(w.message) == "Selected symmetric algorithm not in key preferences"
        assert w.filename == __file__

        w = recwarn.pop(UserWarning)
        assert str(w.message) == "Selected hash algorithm not in key preferences"
        assert w.filename == __file__

        w = recwarn.pop(UserWarning)
        assert str(w.message) == "Selected compression algorithm not in key preferences"
        assert w.filename == __file__

    def test_verify_typeerror(self):
        with pytest.raises(TypeError):
            self.rsa_1_sec.verify(12)

        with pytest.raises(TypeError):
            self.rsa_1_sec.verify("asdf", signature=12)

    def test_verify_nosigs(self):
        msg = PGPMessage.new('tests/testdata/lit')
        with pytest.raises(PGPError):
            self.rsa_1_sec.verify(msg)

    # def test_verify_invalid(self, sec):
    #     sig = sec.sign(_read('tests/testdata/lit'))
    #     assert not sec.verify(_read('tests/testdata/lit2'), sig)

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

    def test_encrypt_insecure_cipher(self):
        msg = PGPMessage.new('asdf')
        with pytest.raises(PGPInsecureCipher):
            msg.encrypt('QwertyUiop', cipher=SymmetricKeyAlgorithm.IDEA)

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
