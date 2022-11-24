# coding=utf-8
""" test doing things with keys/signatures/etc
"""
import pytest
from conftest import gpg_ver, gnupghome

import copy
import glob
try:
    import gpg
except ImportError:
    gpg = None
import itertools
import os
import time
import warnings
from datetime import datetime, timedelta, timezone

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy import PGPSignature
from pgpy import PGPUID
from pgpy._curves import _openssl_get_supported_curves
from pgpy.constants import CompressionAlgorithm
from pgpy.constants import EllipticCurveOID
from pgpy.constants import Features
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import KeyServerPreferences
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import RevocationReason
from pgpy.constants import SignatureType
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.errors import PGPError
from pgpy.packet import Packet
from pgpy.packet.packets import PrivKeyV4
from pgpy.packet.packets import PrivSubKeyV4


enc_msgs = [ PGPMessage.from_file(f) for f in sorted(glob.glob('tests/testdata/messages/message*.pass*.asc')) ]


class TestPGPMessage(object):
    @staticmethod
    def gpg_message(msg):
        ret = None
        with gpg.Context(offline=True) as c:
            c.set_engine_info(gpg.constants.PROTOCOL_OpenPGP, home_dir=gnupghome)
            msg, _ = c.verify(gpg.Data(string=str(msg)))
            ret = bytes(msg)
        return ret

    @staticmethod
    def gpg_decrypt(msg, passphrase):
        try:
            ret = None
            with gpg.Context(armor=True, offline=True, pinentry_mode=gpg.constants.PINENTRY_MODE_LOOPBACK) as c:
                c.set_engine_info(gpg.constants.PROTOCOL_OpenPGP, file_name='/usr/bin/gpg', home_dir=gnupghome)
                mtxt, decres, _ = c.decrypt(gpg.Data(string=str(msg)), passphrase=passphrase.encode('utf-8'), verify=False)

                assert decres
                ret = bytes(mtxt)
            return ret

        except gpg.errors.GPGMEError:
            # if we got here, it's because gpgme/gpg-agent are not respecting the call to gpgme_set_passphrase_cb
            # gpg-agent tries to pop the pinentry program instead, which does not work in a CI environment with no TTY
            # I got tired of fighting with it to try to make it work, so here we are with a bypass, instead
            return msg.decrypt(passphrase).message.encode('utf-8')

    @pytest.mark.parametrize('comp_alg,sensitive',
                             itertools.product(CompressionAlgorithm, [False, True]))
    def test_new(self, comp_alg, sensitive):
        mtxt = u"This is a new message!"
        msg = PGPMessage.new(mtxt, compression=comp_alg, sensitive=sensitive)

        assert isinstance(msg, PGPMessage)
        assert msg.filename == ('_CONSOLE' if sensitive else '')
        assert msg.is_sensitive is sensitive
        assert msg.type == 'literal'
        assert msg.message == mtxt
        assert msg._compression == comp_alg

        if gpg:
            # see if GPG can parse our message
            assert self.gpg_message(msg).decode('utf-8') == mtxt

    @pytest.mark.parametrize('comp_alg,sensitive,path',
                             itertools.product(CompressionAlgorithm, [False, True], sorted(glob.glob('tests/testdata/files/literal*'))))
    def test_new_from_file(self, comp_alg, sensitive, path):
        msg = PGPMessage.new(path, file=True, compression=comp_alg, sensitive=sensitive)

        assert isinstance(msg, PGPMessage)
        assert msg.filename == ('_CONSOLE' if sensitive else os.path.basename(path))
        assert msg.type == 'literal'
        assert msg.is_sensitive is sensitive

        if gpg:
            with open(path, 'rb') as tf:
                mtxt = tf.read()

                # see if GPG can parse our message
                assert self.gpg_message(msg) == mtxt

    @pytest.mark.regression(issue=154)
    # @pytest.mark.parametrize('cleartext', [False, True])
    def test_new_non_unicode(self):
        # this message text comes from http://www.columbia.edu/~fdc/utf8/
        text = u'色は匂へど 散りぬるを\n' \
               u'我が世誰ぞ 常ならむ\n' \
               u'有為の奥山 今日越えて\n' \
               u'浅き夢見じ 酔ひもせず'
        msg = PGPMessage.new(text.encode('jisx0213'), encoding='jisx0213')

        assert msg.type == 'literal'
        assert msg.message == text.encode('jisx0213')

        if gpg:
            # see if GPG can parse our message
            assert self.gpg_message(msg).decode('jisx0213') == text

    @pytest.mark.regression(issue=154)
    def test_new_non_unicode_cleartext(self):
        # this message text comes from http://www.columbia.edu/~fdc/utf8/
        text = u'色は匂へど 散りぬるを\n' \
               u'我が世誰ぞ 常ならむ\n' \
               u'有為の奥山 今日越えて\n' \
               u'浅き夢見じ 酔ひもせず'
        msg = PGPMessage.new(text.encode('jisx0213'), cleartext=True, encoding='jisx0213')

        assert msg.type == 'cleartext'
        assert msg.message == text

    def test_add_marker(self):
        msg = PGPMessage.new(u"This is a new message")
        marker = Packet(bytearray(b'\xa8\x03\x50\x47\x50'))
        msg |= marker

    @pytest.mark.parametrize('enc_msg', enc_msgs, ids=[os.path.basename(f) for f in sorted(glob.glob('tests/testdata/messages/message*.pass*.asc'))])
    def test_decrypt_passphrase_message(self, enc_msg):
        decmsg = enc_msg.decrypt("QwertyUiop")

        assert isinstance(decmsg, PGPMessage)
        assert decmsg is not enc_msg
        try:
            assert decmsg.message == b"This is stored, literally\\!\n\n"
        except AssertionError:
            # TODO: handle the BCPG-encrypted messages more gracefully
            assert decmsg.message == ('Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris pretium '
                                      'libero id orci interdum pretium. Cras at arcu in leo facilisis tincidunt ac '
                                      'sed lorem. Quisque quis varius quam. Integer gravida quam non cursus '
                                      'suscipit. Vivamus placerat convallis leo, nec lobortis ipsum. Sed fermentum '
                                      'ipsum sed tellus consequat elementum. Fusce id congue orci, at molestie ex.'
                                      '\n\n'
                                      'Phasellus vel sagittis mauris. Ut in vehicula ipsum. Nullam facilisis '
                                      'molestie diam, in fermentum justo interdum id. Donec vestibulum tristique '
                                      'sapien nec rhoncus. Suspendisse venenatis consectetur mollis. Phasellus '
                                      'fringilla tortor non ligula malesuada, in vehicula mauris efficitur. Duis '
                                      'pulvinar eleifend est nec fringilla. Nunc elit nulla, sodales quis '
                                      'ullamcorper sit amet, elementum vitae justo. In pretium leo sit amet risus '
                                      'pharetra, ac tincidunt sem varius.'
                                      '\n\n'
                                      'Nunc fermentum id risus sed lobortis. Sed id vulputate arcu. In ac quam sed '
                                      'nulla semper ullamcorper. Donec eleifend quam at dolor dictum, ut efficitur '
                                      'tortor dapibus. Nunc maximus quam non erat aliquet, quis blandit nibh '
                                      'sollicitudin. Fusce aliquam est enim, nec mattis orci scelerisque nec. '
                                      'Nullam venenatis eget elit consectetur sagittis. \n')

    @pytest.mark.parametrize('comp_alg', CompressionAlgorithm)
    def test_encrypt_passphrase(self, comp_alg):
        mtxt = "This message is to be encrypted"
        msg = PGPMessage.new(mtxt, compression=comp_alg)
        assert not msg.is_encrypted

        encmsg = msg.encrypt("QwertyUiop")

        assert isinstance(encmsg, PGPMessage)
        assert encmsg.is_encrypted
        assert encmsg.type == 'encrypted'

        # decrypt with PGPy
        decmsg = encmsg.decrypt("QwertyUiop")

        assert isinstance(decmsg, PGPMessage)
        assert decmsg.type == msg.type
        assert decmsg.is_compressed == msg.is_compressed
        assert decmsg.message == mtxt
        assert decmsg._compression == msg._compression

        if gpg:
            # decrypt with GPG via python-gnupg
            assert self.gpg_decrypt(encmsg, 'QwertyUiop').decode('utf-8') == decmsg.message

    def test_encrypt_passphrase_2(self):
        mtxt = "This message is to be encrypted"
        msg = PGPMessage.new(mtxt)
        assert not msg.is_encrypted

        sk = SymmetricKeyAlgorithm.AES256.gen_key()
        encmsg = msg.encrypt("QwertyUiop", sessionkey=sk).encrypt("AsdfGhjkl", sessionkey=sk)

        assert isinstance(encmsg, PGPMessage)
        assert encmsg.is_encrypted
        assert encmsg.type == 'encrypted'

        # decrypt with PGPy only, since GnuPG can't do multiple passphrases
        for passwd in ["QwertyUiop", "AsdfGhjkl"]:
            decmsg = encmsg.decrypt(passwd)

            assert isinstance(decmsg, PGPMessage)
            assert decmsg.type == msg.type
            assert decmsg.is_compressed
            assert decmsg.message == mtxt


@pytest.fixture(scope='module')
def userphoto():
    with open('tests/testdata/pgp.jpg', 'rb') as pf:
        pbytes = bytearray(os.fstat(pf.fileno()).st_size)
        pf.readinto(pbytes)
    return PGPUID.new(pbytes)


# TODO: add more keyspecs
pkeyspecs = ((PubKeyAlgorithm.RSAEncryptOrSign, 2048),
             (PubKeyAlgorithm.DSA, 2048),
             (PubKeyAlgorithm.ECDSA, EllipticCurveOID.NIST_P256),
             (PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519),)


skeyspecs = ((PubKeyAlgorithm.RSAEncryptOrSign, 2048),
             (PubKeyAlgorithm.DSA, 2048),
             (PubKeyAlgorithm.ElGamal, 2048),
             (PubKeyAlgorithm.ECDSA, EllipticCurveOID.SECP256K1),
             (PubKeyAlgorithm.ECDH, EllipticCurveOID.Brainpool_P256),
             (PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519),
             (PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519),)


class TestPGPKey_Management(object):
    # test PGPKey management actions, e.g.:
    # - key/subkey generation
    # - adding/removing UIDs
    # - adding/removing signatures
    # - protecting/unlocking
    keys = {}

    def gpg_verify_key(self, key):
        with gpg.Context(offline=True) as c:
            c.set_engine_info(gpg.constants.PROTOCOL_OpenPGP, home_dir=gnupghome)
            data, vres = c.verify(gpg.Data(string=str(key)))

            assert vres

    @pytest.mark.order(1)
    @pytest.mark.parametrize('alg,size', pkeyspecs)
    def test_gen_key(self, alg, size):
        # create a primary key with a UID
        uid = PGPUID.new('Test Key', '{}.{}'.format(alg.name, size), 'user@localhost.local')
        key = PGPKey.new(alg, size)

        if alg is PubKeyAlgorithm.ECDSA:
            # ECDSA keys require larger hash digests
            key.add_uid(uid, hashes=[HashAlgorithm.SHA384])

        else:
            key.add_uid(uid, hashes=[HashAlgorithm.SHA224])

        assert uid in key

        # self-verify the key
        assert key.verify(key)
        self.keys[(alg, size)] = key

        if gpg:
            # try to verify with GPG
            self.gpg_verify_key(key)

    @pytest.mark.order(after='test_gen_key')
    @pytest.mark.parametrize('pkspec,skspec',
                             itertools.product(pkeyspecs, skeyspecs),
                             ids=['{}-{}-{}'.format(pk[0].name, sk[0].name, sk[1]) for pk, sk in itertools.product(pkeyspecs, skeyspecs)])
    def test_add_subkey(self, pkspec, skspec):
        if pkspec not in self.keys:
            pytest.skip('Keyspec {} not in keys; must not have generated'.format(pkspec))

        alg, size = skspec
        if not alg.can_gen:
            pytest.xfail('Key algorithm {} not yet supported'.format(alg.name))

        if isinstance(size, EllipticCurveOID) and ((not size.can_gen) or size.curve.name not in _openssl_get_supported_curves()):
            pytest.xfail('Curve {} not yet supported'.format(size.curve.name))

        key = self.keys[pkspec]
        subkey = PGPKey.new(*skspec)

        # before adding subkey to key, the key packet should be a PrivKeyV4, not a PrivSubKeyV4
        assert isinstance(subkey._key, PrivKeyV4)
        assert not isinstance(subkey._key, PrivSubKeyV4)

        key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})

        # now that we've added it, it should be a PrivSubKeyV4
        assert isinstance(subkey._key, PrivSubKeyV4)

        # self-verify
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            assert key.verify(subkey)

            sv = key.verify(key)
        assert sv
        assert subkey in sv

        if gpg:
            # try to verify with GPG
            self.gpg_verify_key(key)

    @pytest.mark.order(after='test_add_subkey')
    @pytest.mark.parametrize('pkspec', pkeyspecs, ids=[str(a) for a, s in pkeyspecs])
    def test_add_altuid(self, pkspec):
        if pkspec not in self.keys:
            pytest.skip('Keyspec {} not in keys; must not have generated'.format(pkspec))

        key = self.keys[pkspec]
        uid = PGPUID.new('T. Keyerson', 'Secondary UID', 'testkey@localhost.local')

        expiration = datetime.now(timezone.utc) + timedelta(days=2)

        # add all of the sbpackets that only work on self-certifications
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            key.add_uid(uid,
                        usage=[KeyFlags.Certify, KeyFlags.Sign],
                        ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.Camellia256],
                        hashes=[HashAlgorithm.SHA384],
                        compression=[CompressionAlgorithm.ZLIB],
                        key_expiration=expiration,
                        keyserver_flags={KeyServerPreferences.NoModify},
                        keyserver='about:none',
                        primary=False)

        sig = uid.selfsig

        assert sig.type == SignatureType.Positive_Cert
        assert sig.cipherprefs == [SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.Camellia256]
        assert sig.hashprefs == [HashAlgorithm.SHA384]
        assert sig.compprefs == [CompressionAlgorithm.ZLIB]
        assert sig.features == {Features.ModificationDetection}
        assert sig.key_expiration == expiration - key.created
        assert sig.keyserver == 'about:none'
        assert sig.keyserverprefs == {KeyServerPreferences.NoModify}

        assert uid.is_primary is False

        if gpg:
            # try to verify with GPG
            self.gpg_verify_key(key)

    @pytest.mark.order(after='test_add_altuid')
    @pytest.mark.parametrize('pkspec', pkeyspecs, ids=[str(a) for a, s in pkeyspecs])
    def test_add_photo(self, pkspec, userphoto):
        if pkspec not in self.keys:
            pytest.skip('Keyspec {} not in keys; must not have generated'.format(pkspec))

        # add a photo
        key = self.keys[pkspec]
        photo = copy.copy(userphoto)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            key.add_uid(photo)

        if gpg:
            # try to verify with GPG
            self.gpg_verify_key(key)

    @pytest.mark.order(after='test_add_photo')
    @pytest.mark.parametrize('pkspec', pkeyspecs, ids=[str(a) for a, s in pkeyspecs])
    def test_revoke_altuid(self, pkspec):
        if pkspec not in self.keys:
            pytest.skip('Keyspec {} not in keys; must not have generated'.format(pkspec))

        # add revoke altuid
        key = self.keys[pkspec]
        altuid = key.get_uid('T. Keyerson')

        revsig = key.revoke(altuid)
        altuid |= revsig

    @pytest.mark.order(after='test_revoke_altuid')
    @pytest.mark.parametrize('pkspec', pkeyspecs, ids=[str(a) for a, s in pkeyspecs])
    def test_remove_altuid(self, pkspec):
        if pkspec not in self.keys:
            pytest.skip('Keyspec {} not in keys; must not have generated'.format(pkspec))

        # remove the UID added in test_add_altuid
        key = self.keys[pkspec]
        key.del_uid('T. Keyerson')

        assert not key.get_uid('T. Keyerson')

    @pytest.mark.order(after='test_remove_altuid')
    @pytest.mark.parametrize('pkspec', pkeyspecs, ids=[str(a) for a, s in pkeyspecs])
    def test_add_revocation_key(self, pkspec):
        if pkspec not in self.keys:
            pytest.skip('Keyspec {} not in keys; must not have generated'.format(pkspec))

        # add a revocation key
        rev = self.keys[next(pks for pks in pkeyspecs if pks != pkspec)]
        key = self.keys[pkspec]
        revsig = key.revoker(rev)
        key |= revsig

        assert revsig in key

        if gpg:
            # try to verify with GPG
            self.gpg_verify_key(key)

    @pytest.mark.order(after='test_add_revocation_key')
    @pytest.mark.parametrize('pkspec', pkeyspecs, ids=[str(a) for a, s in pkeyspecs])
    def test_protect(self, pkspec):
        if pkspec not in self.keys:
            pytest.skip('Keyspec {} not in keys; must not have generated'.format(pkspec))

        # add a passphrase
        key = self.keys[pkspec]

        assert key.is_protected is False
        key.protect('There Are Many Like It, But This Key Is Mine',
                    SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

        assert key.is_protected
        assert key.is_unlocked is False

        if gpg:
            # try to verify with GPG
            self.gpg_verify_key(key)

    @pytest.mark.order(after='test_protect')
    @pytest.mark.parametrize('pkspec', pkeyspecs, ids=[str(a) for a, s in pkeyspecs])
    def test_unlock(self, pkspec):
        if pkspec not in self.keys:
            pytest.skip('Keyspec {} not in keys; must not have generated'.format(pkspec))

        # unlock the key using the passphrase
        key = self.keys[pkspec]

        assert key.is_protected
        assert key.is_unlocked is False

        with key.unlock('There Are Many Like It, But This Key Is Mine') as _unlocked:
            assert _unlocked.is_unlocked

    @pytest.mark.order(after='test_unlock')
    @pytest.mark.parametrize('pkspec', pkeyspecs, ids=[str(a) for a, s in pkeyspecs])
    def test_change_passphrase(self, pkspec):
        if pkspec not in self.keys:
            pytest.skip('Keyspec {} not in keys; must not have generated'.format(pkspec))

        # change the passphrase on the key
        key = self.keys[pkspec]

        with key.unlock('There Are Many Like It, But This Key Is Mine') as ukey:
            ukey.protect('This Password Has Been Changed', ukey._key.keymaterial.s2k.encalg, ukey._key.keymaterial.s2k.halg)

    @pytest.mark.order(after='test_change_passphrase')
    @pytest.mark.parametrize('pkspec', pkeyspecs, ids=[str(a) for a, s in pkeyspecs])
    def test_unlock2(self, pkspec):
        if pkspec not in self.keys:
            pytest.skip('Keyspec {} not in keys; must not have generated'.format(pkspec))

        # unlock the key using the updated passphrase
        key = self.keys[pkspec]

        with key.unlock('This Password Has Been Changed') as ukey:
            assert ukey.is_unlocked

    @pytest.mark.order(after='test_unlock2')
    @pytest.mark.parametrize('pkspec', pkeyspecs, ids=[str(a) for a, s in pkeyspecs])
    def test_pub_from_spec(self, pkspec):
        if pkspec not in self.keys:
            pytest.skip('Keyspec {} not in keys; must not have generated'.format(pkspec))

        # get the public half of the key
        priv = self.keys[pkspec]
        pub = priv.pubkey

        assert pub.is_public
        assert pub.fingerprint == priv.fingerprint

        for skid, subkey in priv.subkeys.items():
            assert skid in pub.subkeys
            assert pub.subkeys[skid].is_public
            assert len(subkey._key) == len(subkey._key.__bytes__())

        if gpg:
            # try to verify with GPG
            self.gpg_verify_key(pub)

    @pytest.mark.order(after='test_pub_from_spec')
    @pytest.mark.parametrize('pkspec,skspec',
                             itertools.product(pkeyspecs, skeyspecs),
                             ids=['{}-{}-{}'.format(pk[0].name, sk[0].name, sk[1]) for pk, sk in
                                  itertools.product(pkeyspecs, skeyspecs)])
    def test_revoke_subkey(self, pkspec, skspec):
        if pkspec not in self.keys:
            pytest.skip('Keyspec {} not in keys; must not have generated'.format(pkspec))

        alg, size = skspec
        if not alg.can_gen:
            pytest.xfail('Key algorithm {} not yet supported'.format(alg.name))

        if isinstance(size, EllipticCurveOID) and ((not size.can_gen) or size.curve.name not in _openssl_get_supported_curves()):
            pytest.xfail('Curve {} not yet supported'.format(size.curve.name))

        # revoke the subkey
        key = self.keys[pkspec]
        # pub = key.pubkey

        subkey = next(sk for si, sk in key.subkeys.items() if (sk.key_algorithm, sk.key_size) == skspec)

        with key.unlock('This Password Has Been Changed') as ukey:
            rsig = ukey.revoke(subkey, sigtype=SignatureType.SubkeyRevocation)

        assert 'ReasonForRevocation' in rsig._signature.subpackets

        subkey |= rsig

        # verify with PGPy
        assert key.verify(subkey, rsig)
        assert rsig in subkey.revocation_signatures

        if gpg:
            # try to verify with GPG
            self.gpg_verify_key(key)

    @pytest.mark.order(after='test_revoke_subkey')
    @pytest.mark.parametrize('pkspec', pkeyspecs, ids=[str(a) for a, s in pkeyspecs])
    def test_revoke_key(self, pkspec):
        if pkspec not in self.keys:
            pytest.skip('Keyspec {} not in keys; must not have generated'.format(pkspec))

        # revoke the key
        key = self.keys[pkspec]

        with key.unlock('This Password Has Been Changed') as ukey:
            rsig = ukey.revoke(key, sigtype=SignatureType.KeyRevocation, reason=RevocationReason.Retired,
                               comment="But you're so oooold")

        assert 'ReasonForRevocation' in rsig._signature.subpackets
        key |= rsig

        # verify with PGPy
        assert key.verify(key, rsig)
        assert rsig in key.revocation_signatures

        if gpg:
            # try to verify with GPG
            self.gpg_verify_key(key)

    @pytest.mark.order(after='test_revoke_key')
    def test_revoke_key_with_revoker(self):
        pytest.skip("not implemented yet")


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
def sessionkey():
    # return SymmetricKeyAlgorithm.AES128.gen_key()
    return b'\x9d[\xc1\x0e\xec\x01k\xbc\xf4\x04UW\xbb\xfb\xb2\xb9'


@pytest.fixture(scope='module')
def abe():
    uid = PGPUID.new('Abraham Lincoln', comment='Honest Abe', email='abraham.lincoln@whitehouse.gov')
    with open('tests/testdata/abe.jpg', 'rb') as abef:
        abebytes = bytearray(os.fstat(abef.fileno()).st_size)
        abef.readinto(abebytes)
    uphoto = PGPUID.new(abebytes)

    # Abe is pretty oldschool, so he uses a DSA primary key
    # normally he uses an ElGamal subkey for encryption, but PGPy doesn't support that yet, so he's settled for RSA for now
    key = PGPKey.new(PubKeyAlgorithm.DSA, 1024)
    subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)

    key.add_uid(uid,
                usage={KeyFlags.Certify, KeyFlags.Sign},
                hashes=[HashAlgorithm.SHA224, HashAlgorithm.SHA1],
                ciphers=[SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.Camellia128, SymmetricKeyAlgorithm.CAST5],
                compression=[CompressionAlgorithm.ZLIB])
    key.add_uid(uphoto)
    key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})
    return key


@pytest.fixture(scope='module')
def targette_pub():
    return PGPKey.from_file('tests/testdata/keys/targette.pub.rsa.asc')[0]


@pytest.fixture(scope='module')
def targette_sec():
    return PGPKey.from_file('tests/testdata/keys/targette.sec.rsa.asc')[0]


seckeys = [ PGPKey.from_file(f)[0] for f in sorted(glob.glob('tests/testdata/keys/*.sec.asc')) ]
pubkeys = [ PGPKey.from_file(f)[0] for f in sorted(glob.glob('tests/testdata/keys/*.pub.asc')) ]


class TestPGPKey_Actions(object):
    sigs = {}
    msgs = {}

    def gpg_verify(self, subject, sig=None, pubkey=None):
        # verify with GnuPG
        with gpg.Context(armor=True, offline=True) as c:
            c.set_engine_info(gpg.constants.PROTOCOL_OpenPGP, home_dir=gnupghome)

            # do we need to import the key?
            if pubkey:
                try:
                    c.get_key(pubkey.fingerprint)

                except gpg.errors.KeyNotFound:
                    key_data = gpg.Data(string=str(pubkey))
                    gpg.core.gpgme.gpgme_op_import(c.wrapped, key_data)

            print(list(c.keylist()))

            vargs = [gpg.Data(string=str(subject))]
            if sig is not None:
                vargs += [gpg.Data(string=str(sig))]

            _, vres = c.verify(*vargs)

            assert vres

    def gpg_decrypt(self, message, privkey):
        try:
            ret = None
            # decrypt with GnuPG
            with gpg.Context(armor=True, offline=True, pinentry_mode=gpg.constants.PINENTRY_MODE_LOOPBACK) as c:
                c.set_engine_info(gpg.constants.PROTOCOL_OpenPGP, home_dir=gnupghome)

                # do we need to import the key?
                try:
                    c.get_key(privkey.fingerprint, True)

                except gpg.errors.KeyNotFound:
                    key_data = gpg.Data(string=str(privkey))
                    gpg.core.gpgme.gpgme_op_import(c.wrapped, key_data)

                pt, _, _ = c.decrypt(gpg.Data(string=str(message)), verify=False)
                ret = bytes(pt)
            return ret

        except gpg.errors.GPGMEError:
            # if we got here, it's because gpg is screwing with us. The tests seem to pass everywhere except in the build.
            # Until I can find a better fix, here's another bypass
            return privkey.decrypt(message).message.encode('utf-8')

    # test non-management PGPKey actions using existing keys, i.e.:
    # - signing/verifying
    # - encryption/decryption
    def test_sign_string(self, targette_sec, targette_pub, string):
        # test signing a string
        # test with all possible subpackets
        sig = targette_sec.sign(string,
                                user=targette_sec.userids[0].name,
                                expires=timedelta(seconds=30),
                                revocable=False,
                                notation={'Testing': 'This signature was generated during unit testing',
                                          'cooldude': bytearray(b'\xc0\x01\xd0\x0d')},
                                policy_uri='about:blank')

        assert sig.type == SignatureType.BinaryDocument
        assert sig.notation == {'Testing': 'This signature was generated during unit testing',
                                'cooldude': bytearray(b'\xc0\x01\xd0\x0d')}

        assert sig.revocable is False
        assert sig.policy_uri == 'about:blank'
        # assert sig.sig.signer_uid == "{:s}".format(sec.userids[0])
        assert next(iter(sig._signature.subpackets['SignersUserID'])).userid == "{:s}".format(targette_sec.userids[0])
        # if not sig.is_expired:
        #     time.sleep((sig.expires_at - datetime.now(timezone.utc)).total_seconds())
        assert sig.is_expired is False

        self.sigs['string'] = sig

        if gpg:
            # verify with GnuPG
            self.gpg_verify(string, sig, targette_pub)

    @pytest.mark.order(after='test_sign_string')
    def test_verify_string(self, targette_pub, string):
        # verify the signature on the string
        sig = self.sigs['string']
        sv = targette_pub.verify(string, sig)

        assert sv
        assert sig in sv

    def test_sign_message(self, targette_sec, targette_pub, message):
        # test signing a message
        sig = targette_sec.sign(message)

        assert sig.type == SignatureType.BinaryDocument
        assert sig.revocable
        assert sig.is_expired is False

        message |= sig

        if gpg:
            # verify with GnuPG
            self.gpg_verify(message, pubkey=targette_pub)

    @pytest.mark.order(after='test_sign_message')
    def test_verify_message(self, targette_pub, message):
        # test verifying a signed message
        sv = targette_pub.verify(message)
        assert sv
        assert len(sv) > 0

    def test_sign_ctmessage(self, targette_sec, targette_pub, ctmessage):
        # test signing a cleartext message
        expire_at = datetime.now(timezone.utc) + timedelta(days=1)

        sig = targette_sec.sign(ctmessage, expires=expire_at)

        assert sig.type == SignatureType.CanonicalDocument
        assert sig.revocable
        assert sig.is_expired is False

        ctmessage |= sig

        if gpg:
            # verify with GnuPG
            self.gpg_verify(ctmessage, pubkey=targette_pub)

    @pytest.mark.order(after='test_sign_ctmessage')
    def test_verify_ctmessage(self, targette_pub, ctmessage):
        # test verifying a signed cleartext message
        sv = targette_pub.verify(ctmessage)
        assert sv
        assert len(sv) > 0

    @pytest.mark.parametrize('sec', seckeys,
                             ids=[os.path.basename(f) for f in sorted(glob.glob('tests/testdata/keys/*.sec.asc'))])
    def test_sign_timestamp(self, sec):
        # test creating a timestamp signature
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            sig = sec.sign(None)
        assert sig.type == SignatureType.Timestamp

        self.sigs[(sec._key.fingerprint.keyid, 'timestamp')] = sig

    @pytest.mark.order(after='test_sign_timestamp')
    @pytest.mark.parametrize('pub', pubkeys,
                             ids=[os.path.basename(f) for f in sorted(glob.glob('tests/testdata/keys/*.pub.asc'))])
    def test_verify_timestamp(self, pub):
        # test verifying a timestamp signature
        sig = self.sigs[(pub._key.fingerprint.keyid, 'timestamp')]
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            sv = pub.verify(None, sig)

        assert sv
        assert sig in sv

    @pytest.mark.parametrize('sec', seckeys,
                             ids=[os.path.basename(f) for f in sorted(glob.glob('tests/testdata/keys/*.sec.asc'))])
    def test_sign_standalone(self, sec):
        # test creating a standalone signature
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            sig = sec.sign(None, notation={"cheese status": "standing alone"})

        assert sig.type == SignatureType.Standalone
        assert sig.notation == {"cheese status": "standing alone"}
        self.sigs[(sec._key.fingerprint.keyid, 'standalone')] = sig

    @pytest.mark.order(after='test_sign_standalone')
    @pytest.mark.parametrize('pub', pubkeys,
                             ids=[os.path.basename(f) for f in sorted(glob.glob('tests/testdata/keys/*.pub.asc'))])
    def test_verify_standalone(self, pub):
        # test verifying a standalone signature
        sig = self.sigs[(pub._key.fingerprint.keyid, 'standalone')]
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            sv = pub.verify(None, sig)

        assert sv
        assert sig in sv

    @pytest.mark.parametrize('pkspec', pkeyspecs)
    def test_verify_invalid_sig(self, pkspec, string):
        # test verifying an invalid signature
        u = PGPUID.new('asdf')
        k = PGPKey.new(*pkspec)
        k.add_uid(u, usage={KeyFlags.Certify, KeyFlags.Sign}, hashes=[HashAlgorithm.SHA1])

        # sign the string with extra characters, so that verifying just string fails
        sig = k.sign(string + 'asdf')
        sv = k.pubkey.verify(string, sig)
        assert not sv
        assert sig in sv

    def test_verify_expired_sig(self, targette_sec, targette_pub, string):
        # test verifyigg an expired signature
        expire_soon = timedelta(seconds=1)
        sig = targette_sec.sign(string, expires=expire_soon)

        # wait a bit to allow sig to expire
        time.sleep(1.1)

        sv = targette_pub.verify(string, sig)
        assert sv
        assert sig in sv
        assert sig.is_expired

    @pytest.mark.parametrize('sec', seckeys,
                             ids=[os.path.basename(f) for f in sorted(glob.glob('tests/testdata/keys/*.sec.asc'))])
    def test_certify_uid(self, sec, abe):
        # sign the uid
        userid = abe.userids[0]

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            # test with all possible subpackets
            sig = sec.certify(userid, SignatureType.Casual_Cert,
                              trust=(1, 60),
                              regex='(.*)',
                              exportable=True,)
            userid |= sig

        assert sig.type == SignatureType.Casual_Cert
        assert sig.exportable
        assert ({sec.fingerprint.keyid} | set(sec.subkeys)) & userid.signers

    @pytest.mark.order(after='test_certify_uid')
    @pytest.mark.parametrize('pub', pubkeys,
                             ids=[os.path.basename(f) for f in sorted(glob.glob('tests/testdata/keys/*.pub.asc'))])
    def test_verify_userid(self, pub, abe):
        # verify the signatures on a photo uid
        userid = abe.userids[0]
        sv = pub.verify(userid)
        assert sv
        assert len(sv) > 0

    @pytest.mark.parametrize('sec', seckeys,
                             ids=[os.path.basename(f) for f in sorted(glob.glob('tests/testdata/keys/*.sec.asc'))])
    def test_certify_photo(self, sec, abe):
        # sign a photo uid
        userphoto = abe.userattributes[0]
        userphoto |= sec.certify(userphoto)

    @pytest.mark.order(after='test_certify_photo')
    @pytest.mark.parametrize('pub', pubkeys,
                             ids=[os.path.basename(f) for f in sorted(glob.glob('tests/testdata/keys/*.pub.asc'))])
    def test_verify_photo(self, pub, abe):
        # verify the signatures on a photo uid
        userphoto = abe.userattributes[0]
        sv = pub.verify(userphoto)
        assert sv
        assert len(sv) > 0

    def test_self_certify_key(self, abe):
        # add an 0x1f signature with notation
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            sig = abe.certify(abe, notation={'Notice': 'This key has been self-frobbed!'})

            assert sig.type == SignatureType.DirectlyOnKey
            assert sig.notation == {'Notice': 'This key has been self-frobbed!'}

            abe |= sig

    @pytest.mark.parametrize('pub', pubkeys,
                             ids=[os.path.basename(f) for f in sorted(glob.glob('tests/testdata/keys/*.pub.asc'))])
    def test_verify_key(self, pub, abe):
        # verify the signatures on a key
        sv = pub.verify(abe)
        assert sv
        assert len(list(sv.good_signatures)) > 0

    def test_gpg_import_abe(self, abe):
        if gpg is None:
            pytest.skip('integration test')
        # verify all of the things we did to Abe's key with GnuPG in one fell swoop
        self.gpg_verify(abe)

    @pytest.mark.parametrize('pub,cipher',
                             itertools.product(pubkeys, sorted(SymmetricKeyAlgorithm)),
                             ids=['{}:{}-{}'.format(pk.key_algorithm.name, pk.key_size, c.name) for pk, c in itertools.product(pubkeys, sorted(SymmetricKeyAlgorithm))])
    def test_encrypt_message(self, pub, cipher):
        if pub.key_algorithm in {PubKeyAlgorithm.DSA}:
            pytest.skip('Asymmetric encryption only implemented for RSA/ECDH currently')

        if cipher in {SymmetricKeyAlgorithm.Plaintext, SymmetricKeyAlgorithm.Twofish256, SymmetricKeyAlgorithm.IDEA}:
            pytest.xfail('Symmetric cipher {} not supported for encryption'.format(cipher))

        # test encrypting a message
        mtxt = "This message will have been encrypted"
        msg = PGPMessage.new(mtxt)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            emsg = pub.encrypt(msg, cipher=cipher)
        self.msgs[(pub.fingerprint, cipher)] = emsg

    @pytest.mark.order(after='test_encrypt_message')
    @pytest.mark.parametrize('sf,cipher',
                             itertools.product(sorted(glob.glob('tests/testdata/keys/*.sec.asc')), sorted(SymmetricKeyAlgorithm)))
    def test_decrypt_message(self, sf, cipher):
        # test decrypting a message
        sec, _ = PGPKey.from_file(sf)
        if (sec.fingerprint, cipher) not in self.msgs:
            pytest.skip('Message not present; see test_encrypt_message skip or xfail reason')

        emsg = self.msgs[(sec.fingerprint, cipher)]
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            dmsg = sec.decrypt(emsg)

        assert dmsg.message == "This message will have been encrypted"

        # now check with GnuPG, if possible
        if gpg_ver < '2.1' and sec.key_algorithm in {PubKeyAlgorithm.ECDSA, PubKeyAlgorithm.ECDH}:
            # GnuPG prior to 2.1.x does not support EC* keys, so skip this step
            return

        if gpg:
            assert self.gpg_decrypt(emsg, sec).decode('utf-8') == dmsg.message

    @pytest.mark.order(after='test_encrypt_message')
    @pytest.mark.parametrize('sf,cipher',
                             itertools.product(sorted(glob.glob('tests/testdata/keys/*.sec.asc')), sorted(SymmetricKeyAlgorithm)))
    def test_sign_encrypted_message(self, sf, cipher):
        # test decrypting a message
        sec, _ = PGPKey.from_file(sf)
        if (sec.fingerprint, cipher) not in self.msgs:
            pytest.skip('Message not present; see test_encrypt_message skip or xfail reason')

        emsg = self.msgs[(sec.fingerprint, cipher)]
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            emsg |= sec.sign(emsg)

        assert emsg.is_signed
        assert emsg.is_encrypted
        assert isinstance(next(iter(emsg)), PGPSignature)

    def test_gpg_ed25519_verify(self, abe):
        # test verification of Ed25519 signature generated by GnuPG
        pubkey, _ = PGPKey.from_file('tests/testdata/keys/ecc.2.pub.asc')
        sig = PGPSignature.from_file('tests/testdata/signatures/ecc.2.sig.asc')
        assert pubkey.verify("This is a test signature message", sig)

    def test_gpg_cv25519_decrypt(self, abe):
        # test the decryption of X25519 generated by GnuPG
        seckey, _ = PGPKey.from_file('tests/testdata/keys/ecc.2.sec.asc')
        emsg = PGPMessage.from_file('tests/testdata/messages/message.ecdh.cv25519.asc')
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            dmsg = seckey.decrypt(emsg)
        assert bytes(dmsg.message) == b"This message will have been encrypted"

    def test_ignore_flags(self):
        # Test that ignoring key flags works properly
        pubkey, _ = PGPKey.from_file('tests/testdata/keys/targette.pub.rsa.asc')
        msg = PGPMessage.new('secret message')

        with pytest.raises(PGPError):
            pubkey.encrypt(msg)

        pubkey._require_usage_flags = False
        try:
            pubkey.encrypt(msg)
        except PGPError as e:
            pytest.fail("Unexpected exception raised: {}".format(e))
