""" test the functionality of PGPKeyring
"""
import pytest

import glob
import os

import six

from pgpy.packet import Packet

from pgpy import PGPKey
from pgpy import PGPKeyring
from pgpy import PGPMessage
from pgpy import PGPSignature
from pgpy import PGPUID
from pgpy.types import Fingerprint

from conftest import gpg_ver


@pytest.fixture
def un():
    return PGPUID.new(six.u('Temperair\xe9e Youx\'seur'))


@pytest.fixture
def unc():
    return PGPUID.new(six.u('Temperair\xe9e Youx\'seur'), comment=six.u('\u2603'))


@pytest.fixture
def une():
    return PGPUID.new(six.u('Temperair\xe9e Youx\'seur'), email='snowman@not.an.email.addre.ss')


@pytest.fixture
def unce():
    return PGPUID.new(six.u('Temperair\xe9e Youx\'seur'), comment=six.u('\u2603'), email='snowman@not.an.email.addre.ss')


@pytest.fixture
def abe():
    return PGPUID.new('Abraham Lincoln', comment='Honest Abe', email='abraham.lincoln@whitehouse.gov')


@pytest.fixture
def abe_image():
    with open('tests/testdata/abe.jpg', 'rb') as abef:
        abebytes = bytearray(os.path.getsize('tests/testdata/abe.jpg'))
        abef.readinto(abebytes)

    return PGPUID.new(abebytes)


class TestPGPMessage(object):
    params = {
        'msgfile': sorted(glob.glob('tests/testdata/messages/*.asc')),
    }
    ids = {
        'test_load_from_file': [ os.path.basename(f) for f in params['msgfile'] ],
    }

    def test_load_from_file(self, msgfile):
        # TODO: figure out a good way to verify that all went well here, because
        #       PGPy reorders signatures sometimes, and also unwraps compressed messages
        #       so comparing str(msg) to the contents of msgfile doesn't actually work
        msg = PGPMessage.from_file(msgfile)

        with open(msgfile, 'r') as mf:
            mt = mf.read()

            assert len(str(msg)) == len(mt)


class TestPGPUID(object):
    def test_userid(self, abe):
        assert abe.name == 'Abraham Lincoln'
        assert abe.comment == 'Honest Abe'
        assert abe.email == 'abraham.lincoln@whitehouse.gov'
        assert abe.image is None

    def test_userphoto(self, abe_image):
        assert abe_image.name == ""
        assert abe_image.comment == ""
        assert abe_image.email == ""
        with open('tests/testdata/abe.jpg', 'rb') as abef:
            abebytes = bytearray(os.path.getsize('tests/testdata/abe.jpg'))
            abef.readinto(abebytes)
        assert abe_image.image == abebytes

    def test_format(self, un, unc, une, unce):
        assert six.u("{:s}").format(un) == six.u('Temperair\xe9e Youx\'seur')
        assert six.u("{:s}").format(unc) == six.u('Temperair\xe9e Youx\'seur (\u2603)')
        assert six.u("{:s}").format(une) == six.u('Temperair\xe9e Youx\'seur <snowman@not.an.email.addre.ss>')
        assert six.u("{:s}").format(unce) == six.u('Temperair\xe9e Youx\'seur (\u2603) <snowman@not.an.email.addre.ss>')


class TestPGPKey(object):
    params = {
        'kf': sorted(glob.glob('tests/testdata/blocks/*key*.asc'))
    }
    ids = {
        'test_load_from_file':       [ os.path.basename(f).replace('.pub.asc', '').replace('.', '_') for f in params['kf'] ],
        'test_load_from_str':        [ os.path.basename(f).replace('.pub.asc', '').replace('.', '_') for f in params['kf'] ],
        'test_load_from_bytes':      [ os.path.basename(f).replace('.pub.asc', '').replace('.', '_') for f in params['kf'] ],
        'test_load_from_bytearray':  [ os.path.basename(f).replace('.pub.asc', '').replace('.', '_') for f in params['kf'] ],
    }
    # kf = next(iter(sorted(glob.glob('tests/testdata/keys/*.pub.asc'))))
    keyfiles = iter(sorted(glob.glob('tests/testdata/keys/*.pub.asc')))

    def test_load_from_file(self, kf, gpg_keyid_file):
        key, _ = PGPKey.from_file(kf)

        # TODO: maybe store the fingerprint instead of relying on a particular version of GnuPG...?
        if 'ecc' in kf and gpg_ver < '2.1':
            assert key.fingerprint

        else:
            assert key.fingerprint.keyid in gpg_keyid_file(kf.replace('tests/testdata/', ''))

    def test_load_from_str(self, kf, gpg_keyid_file):
        with open(kf, 'r') as tkf:
            key, _ = PGPKey.from_blob(tkf.read())

        # TODO: maybe store the fingerprint instead of relying on a particular version of GnuPG...?
        if 'ecc' in kf and gpg_ver < '2.1':
            assert key.fingerprint

        else:
            assert key.fingerprint.keyid in gpg_keyid_file(kf.replace('tests/testdata/', ''))

    @pytest.mark.regression(issue=140)
    def test_load_from_bytes(self, kf, gpg_keyid_file):
        with open(kf, 'rb') as tkf:
            key, _ = PGPKey.from_blob(tkf.read())

        # TODO: maybe store the fingerprint instead of relying on a particular version of GnuPG...?
        if 'ecc' in kf and gpg_ver < '2.1':
            assert key.fingerprint

        else:
            assert key.fingerprint.keyid in gpg_keyid_file(kf.replace('tests/testdata/', ''))

    @pytest.mark.regression(issue=140)
    def test_load_from_bytearray(self, kf, gpg_keyid_file):
        tkb = bytearray(os.stat(kf).st_size)
        with open(kf, 'rb') as tkf:
            tkf.readinto(tkb)

        key, _ = PGPKey.from_blob(tkb)

        # TODO: maybe store the fingerprint instead of relying on a particular version of GnuPG...?
        if 'ecc' in kf and gpg_ver < '2.1':
            assert key.fingerprint

        else:
            assert key.fingerprint.keyid in gpg_keyid_file(kf.replace('tests/testdata/', ''))


@pytest.fixture(scope='module')
def keyring():
    return PGPKeyring()


class TestPGPKeyring(object):
    def test_load(self, keyring):
        # load from filenames
        keys = keyring.load(glob.glob('tests/testdata/*test.asc'), glob.glob('tests/testdata/signatures/*.key.asc'))

        # keys
        assert all(isinstance(k, Fingerprint) for k in keys)

        # __len__
        assert len(keys) == 10
        assert len(keyring) == 16

        # __contains__
        #  RSA von TestKey
        selectors = ["F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36", "37473B3758C44F36", "58C44F36",
                     "RSA von TestKey", "rsa@test.key"]
        for selector in selectors:
            assert selector in keyring

        #  DSA von TestKey
        selectors = ["EBC8 8A94 ACB1 10F1 BE3F E3C1 2B47 4BB0 2084 C712", "2B474BB02084C712", "2084C712",
                     "DSA von TestKey", "dsa@test.key"]
        for selector in selectors:
            assert selector in keyring

        # fingerprints filtering
        #  we have 10 keys
        assert len(keyring.fingerprints()) == 10
        #  10 public halves, 6 private halves
        assert len(keyring.fingerprints(keyhalf='public')) == 10
        assert len(keyring.fingerprints(keyhalf='private')) == 6
        #  we have 5 primary keys; 5 public and 2 private
        assert len(keyring.fingerprints(keytype='primary')) == 5
        assert len(keyring.fingerprints(keytype='primary', keyhalf='public')) == 5
        assert len(keyring.fingerprints(keytype='primary', keyhalf='private')) == 2
        #  and the other 5; 5 public and 4 private
        assert len(keyring.fingerprints(keytype='sub')) == 5
        assert len(keyring.fingerprints(keytype='sub', keyhalf='public')) == 5
        assert len(keyring.fingerprints(keytype='sub', keyhalf='private')) == 4

        # now test sorting:
        rvt = keyring._get_keys("RSA von TestKey")
        assert len(rvt) == 2
        assert not rvt[0].is_public
        assert rvt[1].is_public

    def test_select_fingerprint(self, keyring):
        for fp, name in [("F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36", "RSA von TestKey"),
                         (six.u("F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36"), six.u("RSA von TestKey")),
                         (Fingerprint("F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36"), "RSA von TestKey"),
                         ("EBC8 8A94 ACB1 10F1 BE3F E3C1 2B47 4BB0 2084 C712", "DSA von TestKey"),
                         (six.u("EBC8 8A94 ACB1 10F1 BE3F E3C1 2B47 4BB0 2084 C712"), six.u("DSA von TestKey")),
                         (Fingerprint("EBC8 8A94 ACB1 10F1 BE3F E3C1 2B47 4BB0 2084 C712"), "DSA von TestKey"),]:
            with keyring.key(fp) as key:
                assert key.fingerprint == fp
                assert key.userids[0].name == name

    def test_select_keyid(self, keyring):
        with keyring.key("37473B3758C44F36") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with keyring.key("2B474BB02084C712") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_shortid(self, keyring):
        with keyring.key("58C44F36") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with keyring.key("2084C712") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_name(self, keyring):
        with keyring.key("RSA von TestKey") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with keyring.key("DSA von TestKey") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_comment(self, keyring):
        with keyring.key("2048-bit RSA") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with keyring.key("2048-bit DSA") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_email(self, keyring):
        with keyring.key("rsa@test.key") as rsa:
            assert rsa.userids[0].name == "RSA von TestKey"

        with keyring.key("dsa@test.key") as dsa:
            assert dsa.userids[0].name == "DSA von TestKey"

    def test_select_pgpsignature(self, keyring):
        sig = PGPSignature()
        with open('tests/testdata/signatures/debian-sid.sig.asc', 'r') as sigf:
            sig.parse(sigf.read())

        with keyring.key(sig) as sigkey:
            assert sigkey.fingerprint.keyid == sig.signer

    def test_select_pgpmessage(self, keyring):
        m1 = PGPMessage()
        with open('tests/testdata/messages/message.rsa.cast5.asc', 'r') as m1f:
            m1.parse(m1f.read())

        with keyring.key(m1) as rsakey:
            assert rsakey.fingerprint == "00EC FAF5 48AE B655 F861  8193 EEE0 97A0 17B9 79CA"
            assert rsakey.parent.fingerprint == "F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36"

    def test_unload_key(self, keyring):
        with keyring.key("Test Repository Signing Key") as key:
            keyring.unload(key)

        # is the key and its subkeys actually gone?
        assert id(key) not in keyring._keys
        for pkid in iter(id(sk) for sk in key.subkeys.values()):
            assert pkid not in keyring._keys

        # aliases
        # userid components
        assert "Test Repository Signing Key" not in keyring
        assert "KUS" not in keyring
        assert "usc-kus@securityinnovation.com" not in keyring

        # fingerprints
        assert "513B 160A A994 8C1F 3D77 952D CE57 0774 D0FD CA20" not in keyring

        # keyid(s)
        assert "CE570774D0FDCA20" not in keyring

        # shortids
        assert "D0FDCA20" not in keyring

    def test_unload_key_half(self, keyring):
        with keyring.key('RSA von TestKey') as key:
            keyring.unload(key)

        # key was unloaded for real
        assert id(key) not in keyring._keys

        # but it was not a unique alias, because we only unloaded half of the key
        # userid components
        assert 'RSA von TestKey' in keyring
        assert '2048-bit RSA' in keyring
        assert 'rsa@test.key' in keyring

        # fingerprint, keyid, shortid
        assert 'F429 4BC8 094A 7E05 85C8  5E86 3747 3B37 58C4 4F36' in keyring
        assert '37473B3758C44F36' in keyring
        assert '58C44F36' in keyring
