""" test doing things with keys/signatures/etc
"""
import pytest

import glob
import os

from contextlib import contextmanager
from warnings import catch_warnings

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy import PGPSignature
from pgpy import PGPUID

from pgpy.errors import PGPDecryptionError
from pgpy.errors import PGPEncryptionError
from pgpy.errors import PGPError

from pgpy.constants import CompressionAlgorithm
from pgpy.constants import ImageEncoding
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import RevocationReason
from pgpy.constants import SignatureType
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import HashAlgorithm


def _pgpmessage(f):
    msg = PGPMessage()
    with open(f, 'r') as ff:
        msg.parse(ff.read())
    return msg

def _pgpmessage_new(f):
    with open(f, 'r') as ff:
        msg = PGPMessage.new(ff.read())
    return msg

def _pgpkey(f):
    key = PGPKey()
    with open(f, 'r') as ff:
        key.parse(ff.read())
    return key

def _pgpsignature(f):
    sig = PGPSignature()
    with open(f, 'r') as ff:
        sig.parse(ff.read())
    return sig

def _read(f, mode='r'):
    with open(f, mode) as ff:
        return ff.read()


class TestExceptions(object):
    def test_pgpkey_verify_wrongkey(self):
        wrongkey = _pgpkey('tests/testdata/signatures/aptapproval-test.key.asc')
        sig = _pgpsignature('tests/testdata/signatures/debian-sid.sig.asc')

        with pytest.raises(PGPError):
            wrongkey.verify(_read('tests/testdata/signatures/debian-sid.subj'), sig)

    def test_pgpkey_decrypt_unencrypted_message(self, recwarn):
        lit = _pgpmessage_new('tests/testdata/lit')
        key = _pgpkey('tests/testdata/keys/rsa.1.sec.asc')
        key.decrypt(lit)

        w = recwarn.pop(UserWarning)
        assert str(w.message) == "This message is not encrypted"
        assert w.filename == __file__

    def test_pgpmessage_decrypt_unsupported_algorithm(self):
        msg = _pgpmessage('tests/testdata/message.enc.twofish.asc')
        with pytest.raises(PGPDecryptionError):
            msg.decrypt("QwertyUiop")

    def test_pgpmessage_decrypt_wrongpass(self):
        msg = _pgpmessage(next(f for f in glob.glob('tests/testdata/messages/message*.pass*.asc')))
        with pytest.raises(PGPDecryptionError):
            msg.decrypt("TheWrongPassword")

    def test_pgpmessage_encrypt_unsupported_algorithm(self):
        lit = _pgpmessage_new('tests/testdata/lit')
        with pytest.raises(PGPEncryptionError):
            lit.encrypt("QwertyUiop", cipher=SymmetricKeyAlgorithm.Twofish256)


class TestPGPMessage(object):
    params = {
        'comp_alg': [ CompressionAlgorithm.Uncompressed, CompressionAlgorithm.ZIP, CompressionAlgorithm.ZLIB,
                      CompressionAlgorithm.BZ2 ],
        'enc_msg':  [ _pgpmessage(f) for f in glob.glob('tests/testdata/messages/message*.pass*.asc') ],
        'lit':      [ _pgpmessage_new('tests/testdata/lit') ],
    }
    def test_new_message(self, comp_alg, write_clean, gpg_import, gpg_print):
        with open('tests/testdata/lit', 'r') as litf:
            msg = PGPMessage.new(litf.read(), compression=comp_alg)

        assert msg.type == 'literal'
        assert msg.message.decode('latin-1') == 'This is stored, literally\!\n\n'

        with write_clean('tests/testdata/cmsg.asc', 'w', str(msg)):
            assert gpg_print('cmsg.asc') == msg.message.decode('latin-1')

    def test_decrypt_passphrase_message(self, enc_msg):
        decmsg = enc_msg.decrypt("QwertyUiop")

        assert isinstance(decmsg, PGPMessage)
        assert decmsg.message == b"This is stored, literally\\!\n\n"

    def test_encrypt_passphrase_message(self, lit, write_clean, gpg_decrypt):
        encmsg = lit.encrypt("QwertyUiop")

        # make sure lit was untouched
        assert not lit.is_encrypted

        # make sure encmsg is encrypted
        assert encmsg.is_encrypted
        assert encmsg.type == 'encrypted'

        # decrypt with PGPy
        decmsg = encmsg.decrypt("QwertyUiop")
        assert isinstance(decmsg, PGPMessage)
        assert decmsg.type == lit.type
        assert decmsg.is_compressed
        assert decmsg.message == lit.message

        # decrypt with GPG
        with write_clean('tests/testdata/semsg.asc', 'w', str(lit)):
            assert gpg_decrypt('./semsg.asc', "QwertyUiop") == "This is stored, literally\!\n\n"

    def test_encrypt_passphrase_message_2(self, lit, write_clean, gpg_decrypt):
        sk = SymmetricKeyAlgorithm.AES256.gen_key()
        encmsg = lit.encrypt("QwertyUiop", sessionkey=sk).encrypt("AsdfGhjkl", sessionkey=sk)

        # make sure lit was untouched
        assert not lit.is_encrypted

        # make sure encmsg is encrypted
        assert encmsg.is_encrypted
        assert encmsg.type == 'encrypted'
        assert len(encmsg._sessionkeys) == 2

        # decrypt with PGPy
        for passphrase in ["QwertyUiop", "AsdfGhjkl"]:
            decmsg = encmsg.decrypt(passphrase)
            assert isinstance(decmsg, PGPMessage)
            assert decmsg.type == lit.type
            assert decmsg.is_compressed
            assert decmsg.message == lit.message


class TestPGPKey(object):
    params = {
        'pub':        [ _pgpkey(f) for f in sorted(glob.glob('tests/testdata/keys/*.pub.asc')) ],
        'sec':        [ _pgpkey(f) for f in sorted(glob.glob('tests/testdata/keys/*.sec.asc')) ],
        'enc':        [ _pgpkey(f) for f in sorted(glob.glob('tests/testdata/keys/*.enc.asc')) ],
        'msg':        [ _pgpmessage(f) for f in sorted(glob.glob('tests/testdata/messages/message*.signed*.asc') +
                                                       glob.glob('tests/testdata/messages/cleartext*.signed*.asc')) ],
        'rsa_encmsg': [ _pgpmessage(f) for f in sorted(glob.glob('tests/testdata/messages/message*.rsa*.asc')) ],
        'sigkey':     [ _pgpkey(f) for f in sorted(glob.glob('tests/testdata/signatures/*.key.asc')) ],
        'sigsig':     [ _pgpsignature(f) for f in sorted(glob.glob('tests/testdata/signatures/*.sig.asc')) ],
        'sigsubj':    sorted(glob.glob('tests/testdata/signatures/*.subj')),
    }
    targettes = [ _pgpkey(f) for f in sorted(glob.glob('tests/testdata/keys/targette*.asc')) ]
    ikeys = [os.path.join(*f.split(os.path.sep)[-2:]) for f in glob.glob('tests/testdata/keys/*.pub.asc')]

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

    def test_unlock(self, enc, sec):
        assert enc.is_protected
        assert not enc.is_unlocked
        assert not sec.is_protected

        lit = _read('tests/testdata/lit')

        # try to sign without unlocking
        with pytest.raises(PGPError):
            enc.sign(lit)

        # try to unlock with the wrong password
        enc.unlock('ClearlyTheWrongPassword')

        # unlock with the correct passphrase
        with enc.unlock('QwertyUiop'), self.assert_warnings():
            assert enc.is_unlocked
            # sign lit
            sig = enc.sign(lit)
            # verify with the unlocked key and its unprotected friend
            assert enc.verify(lit, sig)
            assert sec.verify(lit, sig)

    def test_verify_detached(self, sigkey, sigsig, sigsubj):
        assert sigkey.verify(_read(sigsubj), sigsig)

    def test_verify_message(self, msg):
        with self.assert_warnings():
            for pub in self.params['pub']:
                # assert pub.verify(msg)
                sv = pub.verify(msg)
                if not sv:
                    pytest.fail(','.join(repr(ssj) for ssj in sv.bad_signatures))

    def test_verify_self(self, pub):
        with self.assert_warnings():
            assert pub.verify(pub)

    def test_verify_revochiio(self):
        k = PGPKey()
        k.parse(_read('tests/testdata/blocks/revochiio.asc'))

        with self.assert_warnings():
            sv = k.verify(k)

        assert len(sv._subjects) == 13
        _svtypes = [ s.signature.type for s in sv._subjects ]
        assert SignatureType.CertRevocation in _svtypes
        assert SignatureType.DirectlyOnKey in _svtypes
        assert SignatureType.KeyRevocation in _svtypes
        assert SignatureType.Positive_Cert in _svtypes
        assert SignatureType.Subkey_Binding in _svtypes
        assert SignatureType.PrimaryKey_Binding in _svtypes
        assert SignatureType.SubkeyRevocation in _svtypes
        assert sv

    def test_verify_invalid(self, sec):
        with self.assert_warnings():
            sig = sec.sign(_read('tests/testdata/lit'))
            assert not sec.verify(_read('tests/testdata/lit2'), sig)

    def test_sign_detach(self, sec, write_clean, gpg_import, gpg_verify):
        lit = _read('tests/testdata/lit')
        with self.assert_warnings():
            sig = sec.sign(lit)

            # Verify with PGPy
            assert sec.verify(lit, sig)

        # verify with GPG
        with write_clean('tests/testdata/lit.sig', 'w', str(sig)), \
                gpg_import(*[os.path.join(*f.split(os.path.sep)[-2:]) for f in glob.glob('tests/testdata/keys/*.pub.asc')]):
            assert gpg_verify('./lit', './lit.sig', keyid=sig.signer)

    def test_sign_cleartext(self, write_clean, gpg_import, gpg_verify):
        msg = PGPMessage.new(_read('tests/testdata/lit_de'), cleartext=True)

        with self.assert_warnings():
            for sec in self.params['sec']:
                msg += sec.sign(msg)

            assert len(msg.signatures) == len(self.params['sec'])

            # verify with PGPy
            for pub in self.params['pub']:
                assert pub.verify(msg)

        # verify with GPG
        with write_clean('tests/testdata/lit_de.asc', 'w', str(msg)), \
                gpg_import(*[os.path.join(*f.split(os.path.sep)[-2:]) for f in glob.glob('tests/testdata/keys/*.pub.asc')]):
            assert gpg_verify('./lit_de.asc')

    def test_onepass_sign_message(self, write_clean, gpg_import, gpg_verify):
        msg = PGPMessage.new(_read('tests/testdata/lit'))
        with self.assert_warnings():
            for sec in self.params['sec']:
                msg += sec.sign(msg)

            # verify with PGPy
            for pub in self.params['pub']:
                assert pub.verify(msg)

        # verify with GPG
        with write_clean('tests/testdata/lit.asc', 'w', str(msg)), \
                gpg_import(*[os.path.join(*f.split(os.path.sep)[-2:]) for f in glob.glob('tests/testdata/keys/*.pub.asc')]):
            assert gpg_verify('./lit.asc')

    def test_sign_timestamp(self, sec):
        with self.assert_warnings():
            tsig = sec.sign(None, sigtype=SignatureType.Timestamp)
            # verify with PGPy only; GPG does not support timestamp signatures
            assert sec.verify(None, tsig)

    def test_sign_userid(self, sec, pub, write_clean, gpg_import, gpg_check_sigs):
        for tk in self.targettes:
            with self.assert_warnings():
                # sign tk's first uid generically
                tk.userids[0] += sec.sign(tk.userids[0])

                # verify with PGPy
                assert pub.verify(tk.userids[0])

            # verify with GnuPG
            tkfp = '{:s}.asc'.format(tk.fingerprint.shortid)
            ikeys = self.ikeys
            ikeys.append(os.path.join('.', tkfp))
            with write_clean(os.path.join('tests', 'testdata', tkfp), 'w', str(tk)), gpg_import(*ikeys):
                assert gpg_check_sigs(tk.fingerprint.keyid)

    def test_revoke_certification(self, sec, pub, write_clean, gpg_import, gpg_check_sigs):
        for tk in self.targettes:
            # we should have already signed the key in test_sign_userid above
            assert sec.fingerprint.keyid in tk.userids[0].signers

            with self.assert_warnings():
                # revoke that certification!
                tk.userids[0] += sec.sign(tk.userids[0], sigtype=SignatureType.CertRevocation)

                # verify with PGPy
                assert pub.verify(tk.userids[0])

            # verify with GnuPG
            tkfp = '{:s}.asc'.format(tk.fingerprint.shortid)
            ikeys = self.ikeys
            ikeys.append(os.path.join('.', tkfp))
            with write_clean(os.path.join('tests', 'testdata', tkfp), 'w', str(tk)), gpg_import(*ikeys):
                assert gpg_check_sigs(tk.fingerprint.keyid)

    def test_sign_key(self, sec, pub, write_clean, gpg_import, gpg_check_sigs):
        # let's add an 0x1f signature to a key that specifies only symmetric key preferences
        with self.assert_warnings():
            pub += sec.sign(pub,
                            sigtype=SignatureType.DirectlyOnKey,
                            cipherprefs=[SymmetricKeyAlgorithm.AES256,
                                         SymmetricKeyAlgorithm.AES192,
                                         SymmetricKeyAlgorithm.Camellia256,
                                         SymmetricKeyAlgorithm.Camellia192])

            # verify with PGPy
            assert pub.verify(pub)

        # verify with GPG
        kfp = '{:s}.asc'.format(pub.fingerprint.shortid)
        with write_clean(os.path.join('tests', 'testdata', kfp), 'w', str(kfp)), \
                gpg_import(os.path.join('.', kfp)) as kio:
            assert 'invalid self-signature' not in kio

    def test_add_revocation_key(self, sec, pub, write_clean, gpg_import, gpg_check_sigs):
        # this is a fake revocation key id
        revoker = 'C001 CAFE BABE FA11 DEAD  DAED 11AF EBAB EFAC 100C'
        # add a revocation key signature to a key
        with self.assert_warnings():
            pub += sec.sign(pub, sigtype=SignatureType.DirectlyOnKey, revocable=False, revoker=revoker)

            # verify with PGPy
            assert pub.verify(pub)

        # verify with GPG
        kfp = '{:s}.asc'.format(pub.fingerprint.shortid)
        with write_clean(os.path.join('tests', 'testdata', kfp), 'w', str(kfp)), \
                gpg_import(os.path.join('.', kfp)) as kio:
            assert 'invalid self-signature' not in kio

    def test_revoke_key(self, sec, pub, write_clean, gpg_import, gpg_check_sigs):
        with self.assert_warnings():
            rsig = sec.sign(pub, sigtype=SignatureType.KeyRevocation, reason=RevocationReason.Retired,
                            comment="But you're so oooold")
            assert 'ReasonForRevocation' in rsig._signature.subpackets
            pub += rsig

            # verify with PGPy
            assert pub.verify(pub)

        # verify with GPG
        kfp = '{:s}.asc'.format(pub.fingerprint.shortid)
        with write_clean(os.path.join('tests', 'testdata', kfp), 'w', str(kfp)), \
                gpg_import(os.path.join('.', kfp)) as kio:
            assert 'invalid self-signature' not in kio

        # and remove it, for good measure
        pub._signatures.remove(rsig)
        assert rsig not in pub

    def test_sign_subkey(self, sec, pub, write_clean, gpg_import, gpg_check_sigs):
        subkey = next(iter(pub.subkeys.values()))
        with self.assert_warnings():
            # sign the first subkey with an 0x1f signature
            rsig = sec.sign(subkey,
                            sigtype=SignatureType.DirectlyOnKey,
                            cipherprefs=[SymmetricKeyAlgorithm.AES256,
                                         SymmetricKeyAlgorithm.AES192,
                                         SymmetricKeyAlgorithm.Camellia256,
                                         SymmetricKeyAlgorithm.Camellia192])
            subkey += rsig

            # verify with PGPy
            assert pub.verify(subkey)
            sv = pub.verify(pub)
            assert sv
            assert rsig in iter(s.signature for s in sv.good_signatures)

        # verify with GPG
        kfp = '{:s}.asc'.format(pub.fingerprint.shortid)
        with write_clean(os.path.join('tests', 'testdata', kfp), 'w', str(kfp)), \
                gpg_import(os.path.join('.', kfp)) as kio:
            assert 'invalid self-signature' not in kio

        # and remove it, for good measure
        subkey._signatures.remove(rsig)
        assert rsig not in subkey

    def test_revoke_subkey(self, sec, pub, write_clean, gpg_import, gpg_check_sigs):
        subkey = next(iter(pub.subkeys.values()))
        with self.assert_warnings():
            # revoke the first subkey
            rsig = sec.sign(subkey, sigtype=SignatureType.SubkeyRevocation)
            assert 'ReasonForRevocation' in rsig._signature.subpackets
            subkey += rsig

            # verify with PGPy
            assert pub.verify(subkey)
            sv = pub.verify(pub)
            assert sv
            assert rsig in iter(s.signature for s in sv.good_signatures)

        # verify with GPG
        kfp = '{:s}.asc'.format(pub.fingerprint.shortid)
        with write_clean(os.path.join('tests', 'testdata', kfp), 'w', str(kfp)), \
                gpg_import(os.path.join('.', kfp)) as kio:
            assert 'invalid self-signature' not in kio

        # and remove it, for good measure
        subkey._signatures.remove(rsig)
        assert rsig not in subkey

    def test_bind_subkey(self, sec, pub, write_clean, gpg_import, gpg_check_sigs):
        # this is temporary, until subkey generation works
        # replace the first subkey's binding signature with a new one
        subkey = next(iter(pub.subkeys.values()))
        old_usage = subkey.usageflags
        subkey._signatures.clear()

        with self.assert_warnings():
            bsig = sec.sign(subkey,
                            sigtype=SignatureType.Subkey_Binding,
                            usage=old_usage)
            subkey += bsig

            # verify with PGPy
            assert pub.verify(subkey)
            sv = pub.verify(pub)
            assert sv
            assert bsig in iter(s.signature for s in sv.good_signatures)

        # verify with GPG
        kfp = '{:s}.asc'.format(pub.fingerprint.shortid)
        with write_clean(os.path.join('tests', 'testdata', kfp), 'w', str(pub)), \
                gpg_import(os.path.join('.', kfp)) as kio:
            assert 'invalid self-signature' not in kio

    def test_decrypt_rsa_message(self, rsa_encmsg):
        key = PGPKey()
        key.parse(_read('tests/testdata/keys/rsa.1.sec.asc'))

        with self.assert_warnings():
            decmsg = key.decrypt(rsa_encmsg)

        assert isinstance(decmsg, PGPMessage)
        assert decmsg.message == bytearray(b"This is stored, literally\\!\n\n")

    def test_encrypt_rsa_message(self, write_clean, gpg_import, gpg_decrypt):
        pub = PGPKey()
        pub.parse(_read('tests/testdata/keys/rsa.1.pub.asc'))
        sec = PGPKey()
        sec.parse(_read('tests/testdata/keys/rsa.1.sec.asc'))
        msg = PGPMessage.new(_read('tests/testdata/lit'))

        with self.assert_warnings():
            encmsg = pub.encrypt(msg)
            assert isinstance(encmsg, PGPMessage)
            assert encmsg.is_encrypted

            # decrypt with PGPy
            decmsg = sec.decrypt(encmsg)
            assert isinstance(decmsg, PGPMessage)
            assert not decmsg.is_encrypted
            assert decmsg.message == bytearray(b'This is stored, literally\!\n\n')

        # decrypt with GPG
        with write_clean('tests/testdata/aemsg.asc', 'w', str(encmsg)), gpg_import('keys/rsa.1.sec.asc'):
            assert gpg_decrypt('./aemsg.asc') == 'This is stored, literally\!\n\n'

    def test_encrypt_rsa_multi(self, write_clean, gpg_import, gpg_decrypt):
        msg = PGPMessage.new(_read('tests/testdata/lit'))

        with self.assert_warnings():
            sk = SymmetricKeyAlgorithm.AES256.gen_key()
            for rkey in [ k for k in self.params['pub'] if k.key_algorithm == PubKeyAlgorithm.RSAEncryptOrSign ]:
                msg = rkey.encrypt(msg, sessionkey=sk)

            assert isinstance(msg, PGPMessage)
            assert msg.is_encrypted

            # decrypt with PGPy
            for rkey in [ k for k in self.params['sec'] if k.key_algorithm == PubKeyAlgorithm.RSAEncryptOrSign ]:
                decmsg = rkey.decrypt(msg)

                assert not decmsg.is_encrypted
                assert decmsg.message == b'This is stored, literally\!\n\n'

        with write_clean('tests/testdata/aemsg.asc', 'w', str(msg)):
            for kp in glob.glob('tests/testdata/keys/rsa*.sec.asc'):
                with gpg_import(os.path.join(*kp.split(os.path.sep)[-2:])):
                    assert gpg_decrypt('./aemsg.asc') == 'This is stored, literally\!\n\n'

    def test_add_uid(self, sec, pub, write_clean, gpg_import):
        nuid = PGPUID.new(name='Seconduser Aidee',
                          comment='Temporary',
                          email='seconduser.aidee@notarealemailaddress.com')
        sec.add_uid(nuid,
                    usage=[KeyFlags.Authentication],
                    hashprefs=[HashAlgorithm.SHA256, HashAlgorithm.SHA1],
                    cipherprefs=[SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.CAST5],
                    compprefs=[CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed],
                    primary=False)

        u = next(k for k in sec.userids if k.name == 'Seconduser Aidee')
        # assert not u.primary
        assert u.is_uid
        assert u.name == 'Seconduser Aidee'
        assert u.comment == 'Temporary'
        assert u.email == 'seconduser.aidee@notarealemailaddress.com'
        assert u._signatures[0].type == SignatureType.Positive_Cert
        assert u._signatures[0].hashprefs == [HashAlgorithm.SHA256, HashAlgorithm.SHA1]
        assert u._signatures[0].cipherprefs == [SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.CAST5]
        assert u._signatures[0].compprefs == [CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed]

        # verify with PGPy
        with self.assert_warnings():
            assert pub.verify(sec)

        # verify with GPG
        tkfp = '{:s}.asc'.format(sec.fingerprint.shortid)
        with write_clean(os.path.join('tests', 'testdata', tkfp), 'w', str(sec)), \
                gpg_import(os.path.join('.', tkfp)) as kio:
            assert 'invalid self-signature' not in kio

        # remove Seconduser Aidee
        sec.del_uid('Seconduser Aidee')
        assert 'Seconduser Aidee' not in [u.name for u in sec.userids]

    def test_add_photo(self, sec, pub, write_clean, gpg_import):
        photo = bytearray(os.path.getsize('tests/testdata/simple.jpg'))
        with open('tests/testdata/simple.jpg', 'rb') as pf:
            pf.readinto(photo)

        nphoto = PGPUID.new(photo=photo)

        sec.add_uid(nphoto)
        assert nphoto in sec

        u = sec.userattributes[-1]
        assert u.is_ua
        assert u.image.iencoding == ImageEncoding.JPEG
        assert u.image.image == photo

        # verify with PGPy
        with self.assert_warnings():
            assert pub.verify(sec)

        # verify with GPG
        tkfp = '{:s}.asc'.format(sec.fingerprint.shortid)
        with write_clean(os.path.join('tests', 'testdata', tkfp), 'w', str(sec)), \
                gpg_import(os.path.join('.', tkfp)) as kio:
            assert 'invalid self-signature' not in kio

        # remove the new photo
        sec._uids.pop()._parent = None
        assert nphoto not in sec._uids
