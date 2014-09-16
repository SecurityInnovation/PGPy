""" test doing things with keys/signatures/etc
"""
import pytest

import contextlib
import os
import warnings

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy import PGPSignature

from pgpy.errors import PGPError
from pgpy.constants import CompressionAlgorithm
from pgpy.constants import SignatureType
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import HashAlgorithm

from pgpy.packet.packets import OnePassSignature


@contextlib.contextmanager
def ignored(*exceptions):
    try:
        yield
    except exceptions:
        pass


class TestPGPMessage(object):
    def test_new_message(self, comp_alg, gpg_print, pgpdump):
        msg = PGPMessage.new('tests/testdata/lit', compression=comp_alg)

        if comp_alg == CompressionAlgorithm.Uncompressed:
            assert msg.type == 'literal'
        else:
            assert msg.type == 'compressed'
        assert msg.message.decode('latin-1') == 'This is stored, literally\!\n\n'

        with open('tests/testdata/cmsg.asc', 'w') as litf:
            litf.write(str(msg))

        try:
            assert msg.message.decode('latin-1') == gpg_print('cmsg.asc')

        except AssertionError:
            import sys
            sys.stdout.write(pgpdump('tests/testdata/cmsg.asc'))
            assert False
        os.remove('tests/testdata/cmsg.asc')

    def test_message_change_compalg(self, lit, gpg_print):
        # defaults to ZIP
        msg = PGPMessage.new(lit)
        assert msg.type == 'compressed'
        assert msg.message.decode('latin-1') == 'This is stored, literally\!\n\n'

        # change to ZLIB
        msg._contents[0].calg = CompressionAlgorithm.ZLIB
        assert msg.type == 'compressed'
        assert msg.message.decode('latin-1') == 'This is stored, literally\!\n\n'

        with open('tests/testdata/cmsg.asc', 'w') as litf:
            litf.write(str(msg))

        assert msg.message.decode('latin-1') == gpg_print('cmsg.asc')

        os.remove('tests/testdata/cmsg.asc')

    def test_decrypt_passphrase_message(self, passmessage):
        msg = PGPMessage()
        msg.parse(passmessage)

        decmsg = msg.decrypt("QwertyUiop")

        assert isinstance(decmsg, PGPMessage)
        assert decmsg.message == bytearray(b"This is stored, literally\\!\n\n")

    def test_encrypt_passphrase_message(self, lit, gpg_decrypt):
        msg = PGPMessage.new(lit)
        msg.encrypt("QwertyUiop")

        assert msg.type == 'encrypted'

        with open('tests/testdata/semsg.asc', 'w') as litf:
            litf.write(str(msg))

        # decrypt with PGPy
        decmsg = msg.decrypt("QwertyUiop")
        assert isinstance(decmsg, PGPMessage)
        assert decmsg.type == 'compressed'
        assert decmsg.message == bytearray(b"This is stored, literally\\!\n\n")

        # decrypt with GPG
        assert gpg_decrypt('./semsg.asc', "QwertyUiop") == 'This is stored, literally\!\n\n'

        os.remove('tests/testdata/semsg.asc')

    ##TODO: this doesn't always work because decrypting the wrong packet is unpredictable
    # def test_encrypt_two_passphrase_message(self, lit, gpg_decrypt):
    #     msg = PGPMessage.new(lit)
    #     sk = SymmetricKeyAlgorithm.AES256.gen_key()
    #     msg.encrypt("QwertyUiop1", sessionkey=sk)
    #     msg.encrypt("QwertyUiop2", sessionkey=sk)
    #     del sk
    #
    #     with open('tests/testdata/semsg.asc', 'w') as litf:
    #         litf.write(str(msg))
    #
    #     # decrypt with PGPy
    #     for passphrase in ["QwertyUiop1", "QwertyUiop2"]:
    #         decmsg = msg.decrypt(passphrase)
    #         assert isinstance(decmsg, PGPMessage)
    #         assert decmsg.type == 'compressed'
    #         assert decmsg.message == bytearray(b"This is stored, literally\\!\n\n")
    #
    #     # decrypt with GPG; it unfortunately only works with one password (the first one)
    #     assert gpg_decrypt('./semsg.asc', "QwertyUiop1") == 'This is stored, literally\!\n\n'
    #
    #     os.remove('tests/testdata/semsg.asc')


class TestPGPKey(object):
    def test_unlock_encrsakey(self, encrsakey, rsakey):
        ekey = PGPKey()
        ekey.parse(encrsakey)
        rkey = PGPKey()
        rkey.parse(rsakey)

        assert ekey.is_protected
        assert not ekey.is_unlocked
        assert not rkey.is_protected

        with pytest.raises(PGPError):
            ekey.sign('tests/testdata/lit')

        with ekey.unlock('QwertyUiop'), warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert ekey.is_unlocked
            sig = ekey.sign('tests/testdata/lit')
            assert ekey.verify('tests/testdata/lit', sig)
            assert rkey.verify('tests/testdata/lit', sig)

        assert not ekey.is_unlocked

    def test_verify_detach(self, sigf):
        # test verifying signatures in tests/testdata/signatures
        key = PGPKey()
        key.parse(sigf + '.key.asc')
        sig = PGPSignature()
        sig.parse(sigf + '.sig.asc')
        sigv = key.verify(sigf + '.subj', sig)

        assert sigv

    def test_verify_cleartext(self, ctmessage, rsakey, dsakey):
        rsa = PGPKey()
        rsa.parse(rsakey)
        dsa = PGPKey()
        dsa.parse(dsakey)
        ctmsg = PGPMessage()
        ctmsg.parse(ctmessage)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert rsa.verify(ctmsg)
            assert dsa.verify(ctmsg)

    def test_verify_onepass_signed_message(self, rsakey, dsakey):
        opmsg = PGPMessage()
        opmsg.parse('tests/testdata/messages/message.signed_rsa.signed_dsa.asc')
        rkey = PGPKey()
        rkey.parse(rsakey)
        dkey = PGPKey()
        dkey.parse(dsakey)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert rkey.verify(opmsg)
            assert dkey.verify(opmsg)

    def test_verify_signed_message(self, rsakey):
        smsg = PGPMessage()
        smsg.parse('tests/testdata/blocks/message.signed.asc')
        rkey = PGPKey()
        rkey.parse(rsakey)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert rkey.verify(smsg)

    def test_verify_key_selfsigs(self, revkey):
        k = PGPKey()
        k.parse(revkey)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')

            # verify user id(s)
            for uid in k.userids:
                assert k.verify(uid)

            # verify user attribute(s)
            for ua in k.userattributes:
                assert k.verify(ua)

            # verify subkey binding signatures
            for sk in k.subkeys.values():
                assert k.verify(sk)

    def test_verify_key_allsigs(self, revkey):
        k = PGPKey()
        k.parse(revkey)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
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

    def test_verify_rsavontestkey(self, rsakey):
        k = PGPKey()
        k.parse(rsakey)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert k.verify(k)

    def test_verify_dsavontestkey(self, dsakey):
        k = PGPKey()
        k.parse(dsakey)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert k.verify(k)

    def test_verify_wrongkey(self):
        wrongkey = PGPKey()
        wrongkey.parse('tests/testdata/signatures/aptapproval-test.key.asc')

        sig = PGPSignature()
        sig.parse('tests/testdata/signatures/debian-sid.sig.asc')

        with pytest.raises(PGPError):
            wrongkey.verify('tests/testdata/signatures/debian-sid.subj', sig)

    def test_verify_invalid(self, rsakey):
        rkey = PGPKey()
        rkey.parse(rsakey)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            sig = rkey.sign('tests/testdata/lit')
            assert not rkey.verify('tests/testdata/lit2', sig)

    def test_sign_rsa_bindoc(self, rsakey, gpg_verify):
        # test signing binary documents with RSA
        key = PGPKey()
        key.parse(rsakey)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            sig = key.sign('tests/testdata/lit')

        with open('tests/testdata/lit.sig', 'w') as sigf:
            sigf.write(str(sig))

        # verify with PGPy
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert key.verify('tests/testdata/lit', sig)

        # verify with GPG
        assert gpg_verify('./lit', './lit.sig')

        os.remove('tests/testdata/lit.sig')

    def test_sign_dsa_bindoc(self, dsakey, gpg_verify):
        # test signing binary documents with DSA
        key = PGPKey()
        key.parse(dsakey)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            sig = key.sign('tests/testdata/lit')

        with open('tests/testdata/lit.sig', 'w') as sigf:
            sigf.write(str(sig))

        # verify with PGPy
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert key.verify('tests/testdata/lit', sig)

        # verify with GPG
        assert gpg_verify('./lit', './lit.sig')

        os.remove('tests/testdata/lit.sig')

    def test_sign_cleartext(self, rsakey, dsakey, gpg_verify):
        msg = PGPMessage.new('tests/testdata/lit_de', cleartext=True)
        rkey = PGPKey()
        rkey.parse(rsakey)
        dkey = PGPKey()
        dkey.parse(dsakey)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            msg.add_signature(rkey.sign(msg, inline=True))
            msg.add_signature(dkey.sign(msg, inline=True))

        with open('tests/testdata/lit_de.asc', 'w') as isigf:
            isigf.write(str(msg))

        # verify with PGPy
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert rkey.verify(msg)
            assert dkey.verify(msg)

        # verify with GPG
        assert gpg_verify('./lit_de.asc')

        os.remove('tests/testdata/lit_de.asc')

    def test_sign_timestamp(self, rsakey, dsakey, gpg_verify):
        rkey = PGPKey()
        rkey.parse(rsakey)
        dkey = PGPKey()
        dkey.parse(dsakey)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            rtsig = rkey.sign(None, sigtype=SignatureType.Timestamp)
            dtsig = dkey.sign(None, sigtype=SignatureType.Timestamp)
            # verify with PGPy only; GPG does not support timestamp signatures
            assert rkey.verify(None, rtsig)
            assert dkey.verify(None, dtsig)

    def test_sign_message(self, rsakey, dsakey, gpg_verify):
        msg = PGPMessage.new('tests/testdata/lit')
        rkey = PGPKey()
        rkey.parse(rsakey)
        dkey = PGPKey()
        dkey.parse(dsakey)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            msg.add_signature(rkey.sign(msg), onepass=False)
            msg.add_signature(dkey.sign(msg), onepass=False)

        assert not any(isinstance(pkt, OnePassSignature) for pkt in msg._contents)

        with open('tests/testdata/lit.asc', 'w') as litf:
            litf.write(str(msg))

        # verify with PGPy
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert rkey.verify(msg)
            assert dkey.verify(msg)

        # verify with GPG
        assert gpg_verify('./lit.asc')

    def test_onepass_sign_message(self, rsakey, dsakey, gpg_verify):
        msg = PGPMessage.new('tests/testdata/lit')
        rkey = PGPKey()
        rkey.parse(rsakey)
        dkey = PGPKey()
        dkey.parse(dsakey)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            msg.add_signature(rkey.sign(msg))
            msg.add_signature(dkey.sign(msg))

        with open('tests/testdata/lit.asc', 'w') as litf:
            litf.write(str(msg))

        # verify with PGPy
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert rkey.verify(msg)
            assert dkey.verify(msg)

        # verify with GPG
        assert gpg_verify('./lit.asc')

        os.remove('tests/testdata/lit.asc')

    def test_sign_userid(self):
        pytest.skip("not implemented yet")

    def test_sign_key(self):
        pytest.skip("not implemented yet")

    def test_sign_subkey(self):
        pytest.skip("not implemented yet")

    def test_decrypt_rsa_message(self, rsakey, rsamessage):
        key = PGPKey()
        key.parse(rsakey)

        msg = PGPMessage()
        msg.parse(rsamessage)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            decmsg = key.decrypt(msg)

        assert isinstance(decmsg, PGPMessage)
        assert decmsg.message == bytearray(b"This is stored, literally\\!\n\n")

    def test_encrypt_rsa_message(self, rsakey, gpg_decrypt):
        key = PGPKey()
        key.parse(rsakey)

        msg = PGPMessage.new('tests/testdata/lit')

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            encmsg = key.encrypt(msg)

        assert isinstance(encmsg, PGPMessage)
        assert encmsg.is_encrypted

        with open('tests/testdata/aemsg.asc', 'w') as litf:
            litf.write(str(encmsg))

        # decrypt with PGPy
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            decmsg = key.decrypt(encmsg)
        assert isinstance(decmsg, PGPMessage)
        assert not decmsg.is_encrypted
        assert decmsg.message == bytearray(b'This is stored, literally\!\n\n')

        # decrypt with GPG
        assert gpg_decrypt('./aemsg.asc') == 'This is stored, literally\!\n\n'

        os.remove('tests/testdata/aemsg.asc')

    def test_encrypt_rsa_add_recipient(self, rsakey, gpg_decrypt):
        pytest.skip("not implemented yet")

    def test_add_uid(self, rsakey, dsakey, gpg_import):
        rkey = PGPKey()
        rkey.parse(rsakey)
        dkey = PGPKey()
        dkey.parse(dsakey)

        for key in [rkey, dkey]:
            key.add_uid('Seconduser Aidee',
                     comment='Temporary',
                     email="seconduser.aidee@notarealemailaddress.com",
                     usage=[KeyFlags.Authentication],
                     hashprefs=[HashAlgorithm.SHA256, HashAlgorithm.SHA1],
                     cipherprefs=[SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.CAST5],
                     compprefs=[CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed],
                     primary=False)

        for key in [rkey, dkey]:
            with open('tests/testdata/{:s}.asc'.format(key.fingerprint.shortid), 'w') as kf:
                kf.write(str(key))

            # assert not u.primary
            u = [ k for k in key.userids if k.name == 'Seconduser Aidee' ][0]
            assert u.is_uid
            assert u.name == 'Seconduser Aidee'
            assert u.comment == 'Temporary'
            assert u.email == 'seconduser.aidee@notarealemailaddress.com'
            assert u._signatures[0].type == SignatureType.Positive_Cert
            assert u._signatures[0].hashprefs == [HashAlgorithm.SHA256, HashAlgorithm.SHA1]
            assert u._signatures[0].cipherprefs == [SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.CAST5]
            assert u._signatures[0].compprefs == [CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed]

            try:
                # verify with PGPy
                sv = key.verify(key)
                assert sv
                # verify with GPG
                assert gpg_import('./{:s}.asc'.format(key.fingerprint.shortid),
                                  pubring='./tmp.pub.gpg',
                                  secring='./tmp.sec.gpg',
                                  trustdb='./tmp.trust.gpg')

            finally:
                with ignored(FileNotFoundError):
                    os.remove('tests/testdata/tmp.pub.gpg')
                    os.remove('tests/testdata/tmp.pub.gpg~')
                    os.remove('tests/testdata/tmp.sec.gpg')
                    os.remove('tests/testdata/tmp.trust.gpg')
                    os.remove('tests/testdata/{:s}.asc'.format(key.fingerprint.shortid))
