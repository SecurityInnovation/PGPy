""" explicitly test error scenarios
"""
import pytest

import glob
import warnings

from pgpy import PGPKey
from pgpy import PGPKeyring
from pgpy import PGPMessage
from pgpy import PGPSignature
from pgpy import PGPUID
from pgpy.constants import EllipticCurveOID
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.packet import Packet
from pgpy.types import Armorable
from pgpy.types import Fingerprint
from pgpy.types import SignatureVerification
from pgpy.errors import PGPError
from pgpy.errors import PGPDecryptionError
from pgpy.errors import PGPEncryptionError
from pgpy.errors import PGPInsecureCipherError


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


@pytest.fixture(scope='module')
def targette_pub():
    return PGPKey.from_file('tests/testdata/keys/targette.pub.rsa.asc')[0]


@pytest.fixture(scope='module')
def temp_subkey():
    return PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 512)


@pytest.fixture(scope='module')
def temp_key():
    u = PGPUID.new('User')
    k = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 512)
    k.add_uid(u, usage={KeyFlags.Certify, KeyFlags.Sign}, hashes=[HashAlgorithm.SHA1])

    sk = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 512)
    k.add_subkey(sk, usage={KeyFlags.EncryptCommunications})

    return k


key_algs = [ pka for pka in PubKeyAlgorithm if pka.can_gen and not pka.deprecated ]
key_algs_unim = [ pka for pka in PubKeyAlgorithm if not pka.can_gen and not pka.deprecated ]
key_algs_rsa_depr = [ pka for pka in PubKeyAlgorithm if pka.deprecated and pka is not PubKeyAlgorithm.FormerlyElGamalEncryptOrSign ]

key_algs_badsizes = {
    PubKeyAlgorithm.RSAEncryptOrSign: [256],
    PubKeyAlgorithm.DSA: [512],
    PubKeyAlgorithm.ECDSA: [curve for curve in EllipticCurveOID if not curve.can_gen],
    PubKeyAlgorithm.ECDH: [curve for curve in EllipticCurveOID if not curve.can_gen],
}
badkeyspec = [ (alg, size) for alg in key_algs_badsizes.keys() for size in key_algs_badsizes[alg] ]


class TestArmorable(object):
    # some basic test cases specific to the Armorable mixin class
    def test_malformed_base64(self):
        # 'asdf' base64-encoded becomes 'YXNkZg=='
        # remove one of the pad characters and we should get a PGPError
        data = '-----BEGIN PGP SOMETHING-----\n' \
               '\n' \
               'YXNkZg=\n' \
               '=ZEO6\n' \
               '-----END PGP SOMETHING-----\n'
        with pytest.raises(PGPError):
            Armorable.ascii_unarmor(data)


class TestMetaDispatchable(object):
    # test a couple of error cases in MetaDispatchable that affect all packet classes
    def test_parse_bytes_typeerror(self):
        # use a marker packet, but don't wrap it in a bytearray to get a TypeError
        data = b'\xa8\x03\x50\x47\x50'
        with pytest.raises(TypeError):
            Packet(data)

    def test_parse_versioned_header_exception(self):
        # cause an exception during parsing a versioned header by not including the version field
        data = bytearray(b'\xc1\x01')
        with pytest.raises(PGPError):
            Packet(data)

    def test_parse_packet_exceptions(self):
        # use a signature packet with fuzzed fields to get some exceptions
        # original packet is a DSA signature
        data = bytearray(b'\xc2F\x04\x00\x11\x01\x00\x06\x05\x02W\x16\x80\xb0\x00\n\t\x10G\x15FH\x97D\xbc\x0b46\x00'
                         b'\x9fD\xbc\xd7\x87`\xe0\xfeT\x05\xcd\x82\xf5\x9ae\xa9\xb5\x01ii,\x00\x9d\x14\x0b<)\xb4\xc3'
                         b'\x81iu\n\xe3W\xe2\x03\xb1\xc3\xd8p\x89W')

        def fuzz_pkt(slice, val, exc_type):
            d = data[:]
            d[slice] = val

            if exc_type is not None:
                with pytest.raises(exc_type):
                    Packet(d)

            else:
                Packet(d)

        # ensure the base packet works, first
        Packet(data[:])

        class WhatException(Exception): pass

        # unexpected signature type
        fuzz_pkt(3, 0x7f, PGPError)

        # unexpected pubkey algorithm
        fuzz_pkt(4, 0x64, PGPError)

        # unexpected hash algorithm - does not raise an exception during parsing
        fuzz_pkt(5, 0x64, None)


class TestPGPKey(object):
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

    def test_protect_pubkey(self, rsa_pub, recwarn):
        rsa_pub.protect('QwertyUiop', SymmetricKeyAlgorithm.CAST5, HashAlgorithm.SHA1)
        w = recwarn.pop(UserWarning)
        assert str(w.message) == "Public keys cannot be passphrase-protected"
        assert w.filename == __file__

    def test_protect_protected_key(self, rsa_enc, recwarn):
        rsa_enc.protect('QwertyUiop', SymmetricKeyAlgorithm.CAST5, HashAlgorithm.SHA1)

        w = recwarn.pop(UserWarning)
        assert str(w.message) == "This key is already protected with a passphrase - " \
                                 "please unlock it before attempting to specify a new passphrase"
        assert w.filename == __file__

    def test_unlock_wrong_passphrase(self, rsa_enc):
        with pytest.raises(PGPDecryptionError):
            with rsa_enc.unlock('ClearlyTheWrongPassword'):
                pass

    def test_sign_protected_key(self, rsa_enc):
        with pytest.raises(PGPError), warnings.catch_warnings():
            warnings.simplefilter('ignore')
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

    def test_decrypt_protected_key(self, rsa_enc, rsa_pub):
        with pytest.raises(PGPError), warnings.catch_warnings():
            warnings.simplefilter('ignore')
            emsg = rsa_pub.encrypt(PGPMessage.new("asdf"))
            rsa_enc.decrypt(emsg)

    def test_or_typeerror(self, rsa_sec):
        with pytest.raises(TypeError):
            rsa_sec |= 12

    def test_contains_valueerror(self, rsa_sec):
        with pytest.raises(TypeError):
            12 in rsa_sec

    def test_fail_del_uid(self, rsa_sec):
        with pytest.raises(KeyError):
            rsa_sec.del_uid("ASDFDSGSAJGKSAJG")

    def test_encrypt_bad_cipher(self, rsa_pub, recwarn):
        rsa_pub.subkeys['EEE097A017B979CA'].encrypt(PGPMessage.new('asdf'),
                                                    cipher=SymmetricKeyAlgorithm.CAST5)

        relevant_warning_messages = [ str(w.message) for w in recwarn if w.category is UserWarning ]
        assert "Selected symmetric algorithm not in key preferences" in relevant_warning_messages
        assert "Selected compression algorithm not in key preferences" in relevant_warning_messages

    def test_sign_bad_prefs(self, rsa_sec, recwarn):
        rsa_sec.subkeys['2A834D8E5918E886'].sign(PGPMessage.new('asdf'), hash=HashAlgorithm.MD5)

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
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
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

    @pytest.mark.parametrize('badkey', badkeyspec, ids=['{}:{}'.format(alg.name, size if isinstance(size, int) else size.name) for alg, size in badkeyspec])
    def test_new_key_invalid_size(self, badkey):
        key_alg, key_size = badkey
        with pytest.raises(ValueError):
            PGPKey.new(key_alg, key_size)

    @pytest.mark.parametrize('key_alg_unim', key_algs_unim, ids=[alg.name for alg in key_algs_unim])
    def test_new_key_unimplemented_alg(self, key_alg_unim):
        with pytest.raises(NotImplementedError):
            PGPKey.new(key_alg_unim, 512)

    @pytest.mark.parametrize('key_alg_rsa_depr', key_algs_rsa_depr, ids=[alg.name for alg in key_algs_rsa_depr])
    def test_new_key_deprecated_rsa_alg(self, key_alg_rsa_depr, recwarn):
        k = PGPKey.new(key_alg_rsa_depr, 512)

        w = recwarn.pop()
        assert str(w.message) == '{:s} is deprecated - generating key using RSAEncryptOrSign'.format(key_alg_rsa_depr.name)
        # assert w.filename == __file__
        assert k.key_algorithm == PubKeyAlgorithm.RSAEncryptOrSign

    def test_set_pubkey_on_pubkey(self, rsa_pub, targette_pub):
        with pytest.raises(TypeError):
            rsa_pub.pubkey = targette_pub

    def test_set_wrong_pubkey(self, rsa_sec, targette_pub):
        with pytest.raises(ValueError):
            rsa_sec.pubkey = targette_pub

    def test_set_pubkey_already_set(self, rsa_sec, rsa_pub):
        rsa_sec.pubkey = rsa_pub

        assert rsa_sec._sibling is not None
        assert rsa_sec._sibling() is rsa_pub

        with pytest.raises(ValueError):
            rsa_sec.pubkey = rsa_pub

    def test_set_pubkey_privkey(self, rsa_sec, targette_sec):
        with pytest.raises(TypeError):
            rsa_sec.pubkey = targette_sec

    def test_add_subkey_to_pubkey(self, rsa_pub, temp_subkey):
        with pytest.raises(PGPError):
            rsa_pub.add_subkey(temp_subkey)

    def test_add_pubsubkey_to_key(self, rsa_sec, temp_subkey):
        pubtemp = temp_subkey.pubkey

        with pytest.raises(PGPError):
            rsa_sec.add_subkey(pubtemp)

    def test_add_key_with_subkeys_as_subkey(self, rsa_sec, temp_key):
        with pytest.raises(PGPError):
            rsa_sec.add_subkey(temp_key)


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
        with pytest.raises(PGPInsecureCipherError):
            msg.encrypt('QwertyUiop', cipher=SymmetricKeyAlgorithm.IDEA)

    def test_encrypt_sessionkey_wrongtype(self):
        msg = PGPMessage.new('asdf')
        with pytest.raises(TypeError):
            msg.encrypt('asdf', sessionkey=0xabdf1234abdf1234, cipher=SymmetricKeyAlgorithm.AES128)

    def test_parse_wrong_magic(self):
        msgtext = _read('tests/testdata/messages/message.signed.asc').replace('MESSAGE', 'EMSSAGE')
        msg = PGPMessage()
        with pytest.raises(ValueError):
            msg.parse(msgtext)


class TestPGPSignature(object):
    @pytest.mark.parametrize('inp', [12, None])
    def test_or_typeerror(self, inp):
        with pytest.raises(TypeError):
            PGPSignature() | inp

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
    def test_or_typeerror(self):
        u = PGPUID.new("Asdf Qwert")
        with pytest.raises(TypeError):
            u |= 12


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
