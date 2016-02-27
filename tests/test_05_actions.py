# coding=utf-8
""" test doing things with keys/signatures/etc
"""
import pytest

import copy
import glob
import os
import time

from contextlib import contextmanager
from datetime import datetime, timedelta
from warnings import catch_warnings

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy import PGPSignature
from pgpy import PGPUID

from pgpy.constants import CompressionAlgorithm
from pgpy.constants import EllipticCurveOID
from pgpy.constants import Features
from pgpy.constants import HashAlgorithm
from pgpy.constants import ImageEncoding
from pgpy.constants import KeyFlags
from pgpy.constants import KeyServerPreferences
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import RevocationReason
from pgpy.constants import SignatureType
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.constants import TrustLevel

from pgpy.errors import PGPDecryptionError
from pgpy.errors import PGPError

from pgpy.packet.packets import PrivKeyV4
from pgpy.packet.packets import PrivSubKeyV4

from conftest import gpg_ver


def _read(f, mode='r'):
    with open(f, mode) as ff:
        return ff.read()


comp_algs = [ CompressionAlgorithm.Uncompressed, CompressionAlgorithm.ZIP, CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2 ]


class TestPGPMessage(object):
    params = {
        'comp_alg': comp_algs,
        'enc_msg':  [ PGPMessage.from_file(f) for f in glob.glob('tests/testdata/messages/message*.pass*.asc') ],
        'file':    sorted(glob.glob('tests/testdata/files/literal*')),
    }
    ids = {
        'test_new': [ str(ca).split('.')[-1] for ca in comp_algs ],
        'test_new_from_file': [ os.path.basename(fn).replace('.', '_') for fn in params['file'] ],
    }
    attrs = {
        'tests/testdata/files/literal.1.txt':
            [('filename', 'literal.1.txt'),
             ('message', os.linesep.join(['This is stored, literally\!', os.linesep]))],
        'tests/testdata/files/literal.2.txt':
            [('filename', 'literal.2.txt'),
             ('message', os.linesep.join(['This is stored, literally!', os.linesep]))],
        'tests/testdata/files/literal.dashesc.txt':
            [('filename', 'literal.dashesc.txt'),
             ('message', os.linesep.join(['The following items are stored, literally:', '- This one', '- Also this one',
                                          '- And finally, this one!', os.linesep]))],
        'tests/testdata/files/literal.bin':
            [('filename', 'literal.bin'),
             ('message', bytearray(range(256)))],
    }
    def test_new(self, comp_alg, write_clean, gpg_print):
        msg = PGPMessage.new(u"This is a new message!", compression=comp_alg)

        assert msg.type == 'literal'
        assert msg.message == u"This is a new message!"
        assert msg._message.format == 'u'
        assert msg._message.filename == ''
        assert msg.is_compressed is bool(comp_alg != CompressionAlgorithm.Uncompressed)

        with write_clean('tests/testdata/cmsg.asc', 'w', str(msg)):
            assert gpg_print('cmsg.asc') == "This is a new message!"

    def test_new_sensitive(self, write_clean, gpg_print):
        msg = PGPMessage.new("This is a sensitive message!", sensitive=True)

        assert msg.type == 'literal'
        assert msg.message == "This is a sensitive message!"
        assert msg.is_sensitive
        assert msg.filename == '_CONSOLE'

        with write_clean('tests/testdata/csmsg.asc', 'w', str(msg)):
            assert gpg_print('csmsg.asc') == "This is a sensitive message!"

    def test_new_non_unicode(self, write_clean, gpg_print):
        # this message text comes from http://www.columbia.edu/~fdc/utf8/
        text = u'色は匂へど 散りぬるを\n' \
               u'我が世誰ぞ 常ならむ\n' \
               u'有為の奥山 今日越えて\n' \
               u'浅き夢見じ 酔ひもせず\n'
        msg = PGPMessage.new(text.encode('jisx0213'), encoding='jisx0213')

        assert msg.type == 'literal'
        assert msg.message == text.encode('jisx0213')

    def test_new_non_unicode_cleartext(self, write_clean, gpg_print):
        # this message text comes from http://www.columbia.edu/~fdc/utf8/
        text = u'色は匂へど 散りぬるを\n' \
               u'我が世誰ぞ 常ならむ\n' \
               u'有為の奥山 今日越えて\n' \
               u'浅き夢見じ 酔ひもせず\n'

        msg = PGPMessage.new(text.encode('jisx0213'), cleartext=True, encoding='jisx0213')

        assert msg.type == 'cleartext'
        assert msg.message == text

    def test_new_from_file(self, file, write_clean, gpg_print):
        msg = PGPMessage.new(file, file=True)

        assert isinstance(msg, PGPMessage)
        assert msg.type == 'literal'
        assert msg.is_sensitive is False

        assert file in self.attrs
        for attr, expected in self.attrs[file]:
            val = getattr(msg, attr)
            assert val == expected

        with write_clean('tests/testdata/cmsg.asc', 'w', str(msg)):
            out = gpg_print('cmsg.asc')
            if msg._message.format == 'b':
                out = out.encode('latin-1')
            assert out == msg.message

    def test_decrypt_passphrase_message(self, enc_msg):
        decmsg = enc_msg.decrypt("QwertyUiop")

        assert isinstance(decmsg, PGPMessage)
        assert decmsg.message == b"This is stored, literally\\!\n\n"

    def test_encrypt_passphrase(self, write_clean, gpg_decrypt):
        msg = PGPMessage.new("This message is to be encrypted")
        encmsg = msg.encrypt("QwertyUiop")

        # make sure lit was untouched
        assert not msg.is_encrypted

        # make sure encmsg is encrypted
        assert encmsg.is_encrypted
        assert encmsg.type == 'encrypted'

        # decrypt with PGPy
        decmsg = encmsg.decrypt("QwertyUiop")

        assert isinstance(decmsg, PGPMessage)
        assert decmsg.type == msg.type
        assert decmsg.is_compressed
        assert decmsg.message == msg.message

        # decrypt with GPG
        with write_clean('tests/testdata/semsg.asc', 'w', str(encmsg)):
            assert gpg_decrypt('./semsg.asc', "QwertyUiop") == "This message is to be encrypted"

    def test_encrypt_passphrase_2(self, write_clean, gpg_decrypt):
        msg = PGPMessage.new("This message is to be encrypted")
        sk = SymmetricKeyAlgorithm.AES256.gen_key()
        encmsg = msg.encrypt("QwertyUiop", sessionkey=sk).encrypt("AsdfGhjkl", sessionkey=sk)

        # make sure lit was untouched
        assert not msg.is_encrypted

        # make sure encmsg is encrypted
        assert encmsg.is_encrypted
        assert encmsg.type == 'encrypted'
        assert len(encmsg._sessionkeys) == 2

        # decrypt with PGPy
        for passphrase in ["QwertyUiop", "AsdfGhjkl"]:
            decmsg = encmsg.decrypt(passphrase)
            assert isinstance(decmsg, PGPMessage)
            assert decmsg.type == msg.type
            assert decmsg.is_compressed
            assert decmsg.message == msg.message


@pytest.fixture(scope='module')
def string():
    return "This string will be signed"


@pytest.fixture(scope='module')
def message():
    return PGPMessage.new("This is a message!", compression=CompressionAlgorithm.Uncompressed)


@pytest.fixture(scope='module')
def ctmessage():
    return PGPMessage.new("This is a cleartext message!", cleartext=True)


@pytest.fixture(scope='module')
def targette_pub():
    return PGPKey.from_file('tests/testdata/keys/targette.pub.rsa.asc')[0]


@pytest.fixture(scope='module')
def targette_sec():
    return PGPKey.from_file('tests/testdata/keys/targette.sec.rsa.asc')[0]


@pytest.fixture(scope='module')
def userid():
    return PGPUID.new('Abraham Lincoln', comment='Honest Abe', email='abraham.lincoln@whitehouse.gov')


@pytest.fixture(scope='module')
def userphoto():
    with open('tests/testdata/abe.jpg', 'rb') as abef:
        abebytes = bytearray(os.path.getsize('tests/testdata/abe.jpg'))
        abef.readinto(abebytes)
    return PGPUID.new(abebytes)


@pytest.fixture(scope='module')
def sessionkey():
    # return SymmetricKeyAlgorithm.AES128.gen_key()
    return b'\x9d[\xc1\x0e\xec\x01k\xbc\xf4\x04UW\xbb\xfb\xb2\xb9'


def _compare_keys(keyA, keyB):
            for Ai, Bi in zip(keyA._key.keymaterial, keyB._key.keymaterial):
                if Ai != Bi:
                    return False

            return True

# list of tuples of alg, size
key_algs = [ PubKeyAlgorithm.RSAEncryptOrSign, PubKeyAlgorithm.DSA, PubKeyAlgorithm.ECDSA ]
subkey_alg = {
    PubKeyAlgorithm.RSAEncryptOrSign: PubKeyAlgorithm.RSAEncryptOrSign,
    # TODO: when it becomes possible to generate ElGamal keys, change the DSA key's subkey algorithm to ElGamal
    PubKeyAlgorithm.DSA: PubKeyAlgorithm.DSA,
    PubKeyAlgorithm.ECDSA: PubKeyAlgorithm.ECDH,
}
key_alg_size = {
    PubKeyAlgorithm.RSAEncryptOrSign: 1024,
    PubKeyAlgorithm.DSA: 1024,
    PubKeyAlgorithm.ECDSA: EllipticCurveOID.NIST_P256,
    PubKeyAlgorithm.ECDH: EllipticCurveOID.NIST_P256,
}


class TestPGPKey(object):
    params = {
        'pub':        [ PGPKey.from_file(f)[0] for f in sorted(glob.glob('tests/testdata/keys/*.pub.asc')) ],
        'sec':        [ PGPKey.from_file(f)[0] for f in sorted(glob.glob('tests/testdata/keys/*.sec.asc')) ],
        'enc':        [ PGPKey.from_file(f)[0] for f in sorted(glob.glob('tests/testdata/keys/*.enc.asc')) ],
        'sigkey':     [ PGPKey.from_file(f)[0] for f in sorted(glob.glob('tests/testdata/signatures/*.key.asc')) ],
        'sigsig':     [ PGPSignature.from_file(f) for f in sorted(glob.glob('tests/testdata/signatures/*.sig.asc')) ],
        'sigsubj':    sorted(glob.glob('tests/testdata/signatures/*.subj')),
        'key_alg':    key_algs,
    }
    ids = {
        'test_encrypt_message':    [ '-'.join(os.path.basename(f).split('.')[:-2]) for f in sorted(glob.glob('tests/testdata/keys/*.pub.asc')) ],
        'test_decrypt_encmessage': [ '-'.join(os.path.basename(f).split('.')[:-2]) for f in sorted(glob.glob('tests/testdata/keys/*.sec.asc')) ],
        'test_verify_detached':    [ os.path.basename(f).replace('.', '_') for f in sorted(glob.glob('tests/testdata/signatures/*.key.asc')) ],
        'test_new_key':            [ str(ka).split('.')[-1] for ka in key_algs ],
        'test_new_subkey':         [ str(ka).split('.')[-1] for ka in key_algs ],
        'test_pub_from_sec':       [ str(ka).split('.')[-1] for ka in key_algs ],
        'test_gpg_verify_new_key': [ str(ka).split('.')[-1] for ka in key_algs ],
    }
    string_sigs = dict()
    timestamp_sigs = dict()
    standalone_sigs = dict()
    gen_keys = dict()
    encmessage = []

    @contextmanager
    def assert_warnings(self):
        with catch_warnings(record=True) as w:
            try:
                yield

            finally:
                for warning in w:
                    try:
                        assert warning.filename == __file__

                    except AssertionError as e:
                        e.args += (warning.message,)
                        raise

    def test_protect(self, sec):
        if sec.key_algorithm == PubKeyAlgorithm.ECDSA:
            pytest.skip("Cannot properly encrypt ECDSA keys yet")

        assert sec.is_protected is False

        # copy sec so we have a comparison point
        sec2 = copy.deepcopy(sec)
        # ensure that the key material values are the same
        assert _compare_keys(sec, sec2)

        sec2.protect('There Are Many Like It, But This Key Is Mine',
                     SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

        assert sec2.is_protected
        assert sec2.is_unlocked is False
        # ensure that sec2 is now
        assert _compare_keys(sec, sec2) is False

        assert sec2._key.keymaterial.__bytes__()[sec2._key.keymaterial.publen():] not in sec._key.keymaterial.__bytes__()

        # unlock with the correct passphrase and compare the keys
        with sec2.unlock('There Are Many Like It, But This Key Is Mine') as _unlocked:
            assert _unlocked.is_unlocked
            assert _compare_keys(sec, sec2)

    def test_unlock(self, enc, sec):
        assert enc.is_protected
        assert enc.is_unlocked is False
        assert sec.is_protected is False

        # unlock with the correct passphrase
        with enc.unlock('QwertyUiop') as _unlocked, self.assert_warnings():
            assert _unlocked is enc
            assert enc.is_unlocked

    def test_change_passphrase(self, enc):
        enc2 = copy.deepcopy(enc)

        assert enc.is_protected
        assert enc2.is_protected
        assert enc.is_unlocked is False
        assert enc2.is_unlocked is False

        assert enc._key.keymaterial.encbytes == enc2._key.keymaterial.encbytes

        # change the passphrase on enc2
        with enc.unlock('QwertyUiop') as e1u, enc2.unlock('QwertyUiop') as e2u, self.assert_warnings():
            assert _compare_keys(e1u, e2u)
            enc2.protect('AsdfGhjkl', enc2._key.keymaterial.s2k.encalg, enc2._key.keymaterial.s2k.halg)

        assert enc._key.keymaterial.encbytes != enc2._key.keymaterial.encbytes

        # unlock again and verify that we still have the same key hiding in there
        with enc.unlock('QwertyUiop') as e1u, enc2.unlock('AsdfGhjkl') as e2u, self.assert_warnings():
            assert _compare_keys(e1u, e2u)

    def test_verify_detached(self, sigkey, sigsig, sigsubj):
        assert sigkey.verify(_read(sigsubj), sigsig)

    def test_sign_string(self, sec, string, write_clean, gpg_import, gpg_verify):
        with self.assert_warnings():
            # add all of the subpackets we should be allowed to
            sig = sec.sign(string,
                           user=sec.userids[0].name,
                           expires=timedelta(seconds=1),
                           revocable=False,
                           notation={'Testing': 'This signature was generated during unit testing'},
                           policy_uri='about:blank')

        # wait a bit if sig is not yet expired
        assert sig.type == SignatureType.BinaryDocument
        assert sig.notation == {'Testing': 'This signature was generated during unit testing'}
        assert sig.revocable is False
        assert sig.policy_uri == 'about:blank'
        # assert sig.sig.signer_uid == "{:s}".format(sec.userids[0])
        assert next(iter(sig._signature.subpackets['SignersUserID'])).userid == "{:s}".format(sec.userids[0])
        if not sig.is_expired:
            time.sleep((sig.expires_at - datetime.utcnow()).total_seconds())
        assert sig.is_expired

        # verify with GnuPG
        if sig.key_algorithm not in {PubKeyAlgorithm.ECDSA}:
            # TODO: cannot test ECDSA against GnuPG as there isn't an easy way of installing v2.1 yet on CI
            with write_clean('tests/testdata/string', 'w', string), \
                    write_clean('tests/testdata/string.asc', 'w', str(sig)), \
                    gpg_import('./pubtest.asc'):
                assert gpg_verify('./string', './string.asc', keyid=sig.signer)

        self.string_sigs[sec.fingerprint.keyid] = sig

    def test_verify_string(self, pub, string):
        sig = self.string_sigs.pop(pub.fingerprint.keyid)
        with self.assert_warnings():
            sv = pub.verify(string, signature=sig)

        assert sv
        assert len(sv) == 1

    def test_sign_ctmessage(self, sec, ctmessage, write_clean, gpg_import, gpg_verify):
        expire_at = datetime.utcnow() + timedelta(days=1)
        assert isinstance(expire_at, datetime)

        with self.assert_warnings():
            sig = sec.sign(ctmessage, expires=expire_at)

        assert sig.type == SignatureType.CanonicalDocument
        assert sig.revocable
        assert sig.is_expired is False

        ctmessage |= sig

        # verify with GnuPG
        if sig.key_algorithm not in {PubKeyAlgorithm.ECDSA}:
            # TODO: cannot test ECDSA against GnuPG as there isn't an easy way of installing v2.1 yet on CI
            with write_clean('tests/testdata/ctmessage.asc', 'w', str(ctmessage)), gpg_import('./pubtest.asc'):
                assert gpg_verify('./ctmessage.asc', keyid=sig.signer)

    def test_verify_ctmessage(self, pub, ctmessage):
        with self.assert_warnings():
            sv = pub.verify(ctmessage)

        assert sv
        assert len(sv) > 0

    def test_sign_message(self, sec, message):
        with self.assert_warnings():
            sig = sec.sign(message)

        assert sig.type == SignatureType.BinaryDocument
        assert sig.revocable
        assert sig.is_expired is False

        message |= sig

    def test_verify_message(self, pub, message):
        with self.assert_warnings():
            sv = pub.verify(message)

        assert sv
        assert len(sv) > 0

    def test_gpg_verify_message(self, message, write_clean, gpg_import, gpg_verify):
        # verify with GnuPG
        with write_clean('tests/testdata/message.asc', 'w', str(message)), gpg_import('./pubtest.asc'):
            assert gpg_verify('./message.asc')

    def test_encrypt_message(self, pub, message, sessionkey):
        if pub.key_algorithm not in {PubKeyAlgorithm.RSAEncryptOrSign, PubKeyAlgorithm.ECDSA}:
            pytest.skip('Asymmetric encryption only implemented for RSA currently')
            return

        if len(self.encmessage) == 1:
            message = self.encmessage.pop(0)

        with self.assert_warnings():
            enc = pub.encrypt(message, sessionkey=sessionkey, cipher=SymmetricKeyAlgorithm.AES128)
            self.encmessage.append(enc)

    def test_decrypt_encmessage(self, sec, message):
        if sec.key_algorithm not in {PubKeyAlgorithm.RSAEncryptOrSign, PubKeyAlgorithm.ECDSA}:
            pytest.skip('Asymmetric encryption only implemented for RSA and ECDH currently')
            return

        encmessage = self.encmessage[0]

        with self.assert_warnings():
            decmsg = sec.decrypt(encmessage)

        assert decmsg.message == message.message

    def test_gpg_decrypt_encmessage(self, write_clean, gpg_import, gpg_decrypt):
        emsg = self.encmessage.pop(0)
        with write_clean('tests/testdata/aemsg.asc', 'w', str(emsg)):
            # decrypt using RSA
            with gpg_import('./sectest.asc'):
                assert gpg_decrypt('./aemsg.asc', keyid='EEE097A017B979CA')

            # decrypt using ECDH
            if gpg_ver >= '2.1':
                with gpg_import('./keys/ecc.1.sec.asc'):
                    assert gpg_decrypt('./aemsg.asc', keyid='D01055FBCADD268E')

    def test_sign_timestamp(self, sec):
        with self.assert_warnings():
            sig = sec.sign(None)

        assert sig.type == SignatureType.Timestamp
        self.timestamp_sigs[sec.fingerprint.keyid] = sig

    def test_verify_timestamp(self, pub):
        sig = self.timestamp_sigs.pop(pub.fingerprint.keyid)
        with self.assert_warnings():
            sv = pub.verify(None, sig)

        assert sv
        assert len(sv) > 0

    def test_sign_standalone(self, sec):
        with self.assert_warnings():
            sig = sec.sign(None, notation={"cheese status": "standing alone"})

        assert sig.type == SignatureType.Standalone
        assert sig.notation == {"cheese status": "standing alone"}
        self.standalone_sigs[sec.fingerprint.keyid] = sig

    def test_verify_standalone(self, pub):
        sig = self.standalone_sigs.pop(pub.fingerprint.keyid)
        with self.assert_warnings():
            sv = pub.verify(None, sig)

        assert sv
        assert len(sv) > 0

    def test_add_userid(self, userid, targette_sec):
        # add userid to targette_sec
        expire_in = datetime.utcnow() + timedelta(days=2)
        with self.assert_warnings():
            # add all of the subpackets that only work on self-certifications
            targette_sec.add_uid(userid,
                                 usage=[KeyFlags.Certify, KeyFlags.Sign],
                                 ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.Camellia256],
                                 hashes=[HashAlgorithm.SHA384],
                                 compression=[CompressionAlgorithm.ZLIB],
                                 key_expiration=expire_in,
                                 keyserver_flags=0x80,
                                 keyserver='about:none',
                                 primary=False)

        sig = userid.selfsig

        assert sig.type == SignatureType.Positive_Cert
        assert sig.cipherprefs == [SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.Camellia256]
        assert sig.hashprefs == [HashAlgorithm.SHA384]
        assert sig.compprefs == [CompressionAlgorithm.ZLIB]
        assert sig.features == {Features.ModificationDetection}
        assert sig.key_expiration == expire_in - targette_sec.created
        assert sig.keyserver == 'about:none'
        assert sig.keyserverprefs == [KeyServerPreferences.NoModify]

        assert userid.is_primary is False

    def test_remove_userid(self, targette_sec):
        # create a temporary userid, add it, and then remove it
        tempuid = PGPUID.new('Temporary Youx\'seur')
        targette_sec.add_uid(tempuid)

        assert tempuid in targette_sec

        targette_sec.del_uid('Temporary Youx\'seur')
        assert tempuid not in targette_sec

    def test_certify_userid(self, sec, userid):
        with self.assert_warnings():
            # add all of the subpackets that only work on (non-self) certifications
            sig = sec.certify(userid, SignatureType.Casual_Cert,
                              usage=KeyFlags.Authentication,
                              exportable=True,
                              trust=(1, 60),
                              regex=r'.*')

        assert sig.type == SignatureType.Casual_Cert
        assert sig.key_flags == {KeyFlags.Authentication}
        assert sig.exportable
        # assert sig.trust_level == 1
        # assert sig.trust_amount == 60
        # assert sig.regex == r'.*'

        assert {sec.fingerprint.keyid} | set(sec.subkeys) & userid.signers

        userid |= sig

    def test_verify_userid(self, pub, userid):
        # with PGPy
        with self.assert_warnings():
            sv = pub.verify(userid)

        assert sv
        assert len(sv) > 0

    def test_add_photo(self, userphoto, targette_sec):
        with self.assert_warnings():
            targette_sec.add_uid(userphoto)

    def test_certify_photo(self, sec, userphoto):
        with self.assert_warnings():
            userphoto |= sec.certify(userphoto)

    def test_revoke_certification(self, sec, userphoto):
        # revoke the certifications of userphoto
        with self.assert_warnings():
            revsig = sec.revoke(userphoto)

        assert revsig.type == SignatureType.CertRevocation

        userphoto |= revsig

    def test_certify_key(self, sec, targette_sec):
        # let's add an 0x1f signature with notation
        # GnuPG does not like these, so we'll mark it as non-exportable
        with self.assert_warnings():
            sig = sec.certify(targette_sec, exportable=False, notation={'Notice': 'This key has been frobbed!',
                                                                        'Binary': bytearray(b'\xc0\x01\xd0\x0d')})

        assert sig.type == SignatureType.DirectlyOnKey
        assert sig.exportable is False
        assert sig.notation == {'Notice': 'This key has been frobbed!', 'Binary': bytearray(b'\xc0\x01\xd0\x0d')}

        targette_sec |= sig

    def test_self_certify_key(self, targette_sec):
        # let's add an 0x1f signature with notation
        with self.assert_warnings():
            sig = targette_sec.certify(targette_sec, notation={'Notice': 'This key has been self-frobbed!'})

        assert sig.type == SignatureType.DirectlyOnKey
        assert sig.notation == {'Notice': 'This key has been self-frobbed!'}

        targette_sec |= sig

    def test_add_revocation_key(self, sec, targette_sec):
        targette_sec |= targette_sec.revoker(sec)

    def test_verify_key(self, pub, targette_sec):
        with self.assert_warnings():
            sv = pub.verify(targette_sec)
            assert len(list(sv.good_signatures)) > 0
            assert sv

    def test_new_key(self, key_alg):
        # create a key and a user id and add the UID to the key
        uid = PGPUID.new('Hugo Gernsback', 'Science Fiction Plus', 'hugo.gernsback@space.local')
        key = PGPKey.new(key_alg, key_alg_size[key_alg])
        key.add_uid(uid, hashes=[HashAlgorithm.SHA224])

        # self-verify the key
        assert key.verify(key)

        self.gen_keys[key_alg] = key

    def test_new_subkey(self, key_alg):
        key = self.gen_keys[key_alg]
        subkey = PGPKey.new(subkey_alg[key_alg], key_alg_size[subkey_alg[key_alg]])

        assert subkey._key
        assert not isinstance(subkey._key, PrivSubKeyV4)

        # now add the subkey to key and then verify it
        key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})

        # subkey should be a PrivSubKeyV4 now, not a PrivKeyV4
        assert isinstance(subkey._key, PrivSubKeyV4)

        # self-verify
        sv = self.gen_keys[key_alg].verify(self.gen_keys[key_alg])

        assert sv
        assert subkey in sv

    def test_pub_from_sec(self, key_alg):
        priv = self.gen_keys[key_alg]

        pub = priv.pubkey

        assert pub.fingerprint == priv.fingerprint
        assert len(pub._key) == len(pub._key.__bytes__())
        for skid, subkey in priv.subkeys.items():
            assert skid in pub.subkeys
            assert pub.subkeys[skid].is_public
            assert len(subkey._key) == len(subkey._key.__bytes__())

    def test_gpg_verify_new_key(self, key_alg, write_clean, gpg_import, gpg_check_sigs):
        if gpg_ver < '2.1' and key_alg in {PubKeyAlgorithm.ECDSA, PubKeyAlgorithm.ECDH}:
            pytest.skip("GnuPG version in use cannot import/verify ")

        # with GnuPG
        key = self.gen_keys[key_alg]
        with write_clean('tests/testdata/genkey.asc', 'w', str(key)), \
                gpg_import('./genkey.asc') as kio:

            assert 'invalid self-signature' not in kio
            assert gpg_check_sigs(key.fingerprint.keyid, *[skid for skid in key._children.keys()])

    def test_gpg_verify_key(self, targette_sec, write_clean, gpg_import, gpg_check_sigs):
        # with GnuPG
        with write_clean('tests/testdata/targette.sec.asc', 'w', str(targette_sec)), \
                gpg_import('./pubtest.asc', './targette.sec.asc') as kio:
            assert 'invalid self-signature' not in kio
            assert gpg_check_sigs(targette_sec.fingerprint.keyid)

    def test_revoke_key(self, sec, pub, write_clean, gpg_import, gpg_check_sigs):
        with self.assert_warnings():
            rsig = sec.revoke(pub, sigtype=SignatureType.KeyRevocation, reason=RevocationReason.Retired,
                            comment="But you're so oooold")
            assert 'ReasonForRevocation' in rsig._signature.subpackets
            pub |= rsig

            # verify with PGPy
            # assert pub.verify(pub)

        # verify with GPG
        kfp = '{:s}.asc'.format(pub.fingerprint.shortid)
        with write_clean(os.path.join('tests', 'testdata', kfp), 'w', str(kfp)), \
                gpg_import(os.path.join('.', kfp)) as kio:
            assert 'invalid self-signature' not in kio

        # and remove it, for good measure
        pub._signatures.remove(rsig)
        assert rsig not in pub

    def test_revoke_key_with_revoker(self):
        pytest.skip("not implemented yet")

    def test_revoke_subkey(self, sec, pub, write_clean, gpg_import, gpg_check_sigs):
        if sec.key_algorithm == PubKeyAlgorithm.ECDSA:
            pytest.skip("ECDH not implemented yet which causes this test to fail")

        subkey = next(iter(pub.subkeys.values()))
        with self.assert_warnings():
            # revoke the first subkey
            rsig = sec.revoke(subkey, sigtype=SignatureType.SubkeyRevocation)
            assert 'ReasonForRevocation' in rsig._signature.subpackets
            subkey |= rsig

            # verify with PGPy
            assert pub.verify(subkey)
            sv = pub.verify(pub)
            assert sv
            assert rsig in iter(s.signature for s in sv.good_signatures)

        # verify with GnuPG
        kfp = '{:s}.asc'.format(pub.fingerprint.shortid)
        with write_clean(os.path.join('tests', 'testdata', kfp), 'w', str(kfp)), \
                gpg_import(os.path.join('.', kfp)) as kio:
            assert 'invalid self-signature' not in kio

        # and remove it, for good measure
        subkey._signatures.remove(rsig)
        assert rsig not in subkey
