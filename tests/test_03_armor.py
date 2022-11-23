""" test (de)armoring of PGP blocks
"""
import pytest

import glob
import os
from datetime import datetime, timezone

from pgpy.constants import HashAlgorithm
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SignatureType
from pgpy.pgp import PGPKey
from pgpy.pgp import PGPMessage
from pgpy.pgp import PGPSignature
from pgpy.types import Armorable


blocks = sorted(glob.glob('tests/testdata/blocks/*.asc'))
block_attrs = {
    'tests/testdata/blocks/message.ascii.asc':
        [('encrypters',    set()),
         ('filename',      'ascii'),
         ('is_compressed', False),
         ('is_encrypted',  False),
         ('is_signed',     False),
         ('issuers',       set()),
         ('message',       "This is stored, textually!\r\n"),
         ('signers',       set()),
         ('type',          'literal'),],

    'tests/testdata/blocks/message.compressed.asc':
        [('encrypters',    set()),
         ('filename',      'lit'),
         ('is_compressed', True),
         ('is_encrypted',  False),
         ('is_signed',     False),
         ('issuers',       set()),
         ('message',       b"This is stored, literally\\!\n\n"),
         ('signers',       set()),
         ('type',          'literal'),],

    'tests/testdata/blocks/message.literal.asc':
        [('encrypters',    set()),
         ('filename',      'lit'),
         ('is_compressed', False),
         ('is_encrypted',  False),
         ('is_signed',     False),
         ('issuers',       set()),
         ('message',       b"This is stored, literally\\!\n\n"),
         ('signers',       set()),
         ('type',          'literal'),],

    'tests/testdata/blocks/message.onepass.asc':
        [('encrypters',    set()),
         ('filename',      'lit'),
         ('is_compressed', False),
         ('is_encrypted',  False),
         ('is_signed',     True),
         ('issuers',       {'2A834D8E5918E886'}),
         ('message',       b"This is stored, literally\\!\n\n"),
         ('signers',       {'2A834D8E5918E886'}),
         ('type',          'literal'),],

    'tests/testdata/blocks/message.two_onepass.asc':
        [('encrypters',    set()),
         ('filename',      'lit'),
         ('is_compressed', False),
         ('is_encrypted',  False),
         ('is_signed',     True),
         ('issuers',       {'2A834D8E5918E886', 'A5DCDC966453140E'}),
         ('message',       b"This is stored, literally\\!\n\n"),
         ('signers',       {'2A834D8E5918E886', 'A5DCDC966453140E'}),
         ('type',          'literal'),],

    'tests/testdata/blocks/message.signed.asc':
        [('encrypters',    set()),
         ('filename',      'lit'),
         ('is_compressed', False),
         ('is_encrypted',  False),
         ('is_signed',     True),
         ('issuers',       {'2A834D8E5918E886'}),
         ('message',      b"This is stored, literally\\!\n\n"),
         ('signers',       {'2A834D8E5918E886'}),
         ('type',         'literal'),],

    'tests/testdata/blocks/cleartext.asc':
        [('encrypters',    set()),
         ('is_compressed', False),
         ('is_encrypted',  False),
         ('is_signed',     True),
         ('issuers',       {'2A834D8E5918E886'}),
         ('message',       "This is stored, literally\\!\n"),
         ('signers',       {'2A834D8E5918E886'}),
         ('type',          'cleartext'),],

    'tests/testdata/blocks/cleartext.twosigs.asc':
        [('encrypters',    set()),
         ('is_compressed', False),
         ('is_encrypted',  False),
         ('is_signed',     True),
         ('issuers',       {'2A834D8E5918E886', 'A5DCDC966453140E'}),
         ('message',       "This is stored, literally\\!\n"),
         ('signers',       {'2A834D8E5918E886', 'A5DCDC966453140E'}),
         ('type',          'cleartext'),],

    'tests/testdata/blocks/message.encrypted.asc':
        [('encrypters',    {'EEE097A017B979CA'}),
         ('is_compressed', False),
         ('is_encrypted',  True),
         ('is_signed',     False),
         ('issuers',       {'EEE097A017B979CA'}),
         ('signers',       set()),
         ('type',          'encrypted')],

    'tests/testdata/blocks/message.encrypted.signed.asc':
        [('encrypters',    {'EEE097A017B979CA'}),
         ('is_compressed', False),
         ('is_encrypted',  True),
         ('is_signed',     False),
         ('issuers',       {'EEE097A017B979CA'}),
         ('signers',       set()),
         ('type',          'encrypted')],

    'tests/testdata/blocks/message.ecc.encrypted.asc':
        [('encrypters',    {'77CEB7A34089AB73'}),
         ('is_compressed', False),
         ('is_encrypted',  True),
         ('is_signed',     False),
         ('issuers',       {'77CEB7A34089AB73'}),
         ('signers',       set()),
         ('type',          'encrypted')],

    'tests/testdata/blocks/revochiio.asc':
        [('created',       datetime(2014, 9, 11, 22, 55, 53, tzinfo=timezone.utc)),
         ('fingerprint',   "AE15 9FF3 4C1A 2426 B7F8 0F1A 560C F308 EF60 CFA3"),
         ('expires_at',    datetime(2018, 9, 12, 1, 0, 59, tzinfo=timezone.utc)),
         ('is_expired',    True),
         ('is_primary',    True),
         ('is_protected',  False),
         ('is_public',     True),
         ('is_unlocked',   True),
         ('key_algorithm', PubKeyAlgorithm.RSAEncryptOrSign),
         ('magic',         "PUBLIC KEY BLOCK"),
         ('parent',        None),
         ('signers',       {'560CF308EF60CFA3'}),],

    'tests/testdata/blocks/expyro.asc':
        [('created',       datetime(1970, 1, 1, tzinfo=timezone.utc)),
         ('expires_at',    datetime(1970, 1, 2, tzinfo=timezone.utc)),
         ('fingerprint',   '24EB C1B0 29B1 FCF8 29A5  C150 1A48 291A FB91 A533'),
         ('is_expired',    True),],

    'tests/testdata/blocks/rsapubkey.asc':
        [('created',       datetime(2014, 7, 23, 21, 19, 24, tzinfo=timezone.utc)),
         ('expires_at',    None),
         ('fingerprint',   "F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36"),
         ('is_expired',    False),
         ('is_primary',    True),
         ('is_protected',  False),
         ('is_public',     True),
         ('is_unlocked',   True),
         ('key_algorithm', PubKeyAlgorithm.RSAEncryptOrSign),
         ('magic',         "PUBLIC KEY BLOCK"),
         ('parent',        None),
         ('signers',       set()),],

    'tests/testdata/blocks/rsaseckey.asc':
        [('created',       datetime(2014, 7, 23, 21, 19, 24, tzinfo=timezone.utc)),
         ('expires_at',    None),
         ('fingerprint',   "F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36"),
         ('is_expired',    False),
         ('is_primary',    True),
         ('is_protected',  False),
         ('is_public',     False),
         ('is_unlocked',   True),
         ('key_algorithm', PubKeyAlgorithm.RSAEncryptOrSign),
         ('magic',         "PRIVATE KEY BLOCK"),
         ('parent',        None),
         ('signers',       set()),],

    'tests/testdata/blocks/rsasignature.asc':
        [('__sig__',       b'\x70\x38\x79\xd0\x58\x70\x58\x7b\x50\xe6\xab\x8f\x9d\xc3\x46\x2c\x5a\x6b\x98\x96\xcf'
                   b'\x3b\xa3\x79\x13\x08\x6d\x90\x9d\x67\xd2\x48\x7d\xd7\x1a\xa5\x98\xa7\x8f\xca\xe3\x24'
                   b'\xd4\x19\xab\xe5\x45\xc5\xff\x21\x0c\x72\x88\x91\xe6\x67\xd7\xe5\x00\xb3\xf5\x55\x0b'
                   b'\xd0\xaf\x77\xb3\x7e\xa4\x79\x59\x06\xa2\x05\x44\x9d\xd2\xa9\xcf\xb1\xf8\x03\xc1\x90'
                   b'\x81\x87\x36\x1a\xa6\x5c\x79\x98\xfe\xdb\xdd\x23\x54\x69\x92\x2f\x0b\xc4\xee\x2a\x61'
                   b'\x77\x35\x59\x6e\xb2\xe2\x1b\x80\x61\xaf\x2d\x7a\x64\x38\xfe\xe3\x95\xcc\xe8\xa4\x05'
                   b'\x55\x5d'),
         ('cipherprefs',    []),
         ('compprefs',      []),
         ('created',        datetime.fromtimestamp(1402615373, timezone.utc)),
         ('embedded',       False),
         ('exportable',     True),
         ('features',       set()),
         ('hash2',          b'\xc4\x24'),
         ('hashprefs',      []),
         ('hash_algorithm', HashAlgorithm.SHA512),
         ('is_expired',     False),
         ('key_algorithm',  PubKeyAlgorithm.RSAEncryptOrSign),
         ('key_flags',      set()),
         ('keyserver',      ''),
         ('keyserverprefs', []),
         ('magic',          "SIGNATURE"),
         ('notation',       {}),
         ('policy_uri',     ''),
         ('revocable',      True),
         ('revocation_key', None),
         ('signer',         'FCAE54F74BA27CF7'),
         ('type',           SignatureType.BinaryDocument)],

    'tests/testdata/blocks/eccpubkey.asc':
        [('created',       datetime(2010, 9, 17, 20, 33, 49, tzinfo=timezone.utc)),
         ('expires_at',    None),
         ('fingerprint',   "502D 1A53 65D1 C0CA A699 4539 0BA5 2DF0 BAA5 9D9C"),
         ('is_expired',    False),
         ('is_primary',    True),
         ('is_protected',  False),
         ('is_public',     True),
         ('is_unlocked',   True),
         ('key_algorithm', PubKeyAlgorithm.ECDSA),
         ('magic',         "PUBLIC KEY BLOCK"),
         ('parent',        None),
         ('signers',       set()),],

    'tests/testdata/blocks/eccseckey.asc':
        [('created',       datetime(2010, 9, 17, 20, 33, 49, tzinfo=timezone.utc)),
         ('expires_at',    None),
         ('fingerprint',   "502D 1A53 65D1 C0CA A699 4539 0BA5 2DF0 BAA5 9D9C"),
         ('is_expired',    False),
         ('is_primary',    True),
         ('is_protected',  True),
         ('is_public',     False),
         ('is_unlocked',   False),
         ('key_algorithm', PubKeyAlgorithm.ECDSA),
         ('magic',         "PRIVATE KEY BLOCK"),
         ('parent',        None),
         ('signers',       set()),],

    'tests/testdata/blocks/dsaseckey.asc':
        [('created',       datetime(2017, 2, 21, 19, 21, 41, tzinfo=timezone.utc)),
         ('expires_at',    None),
         ('fingerprint',   "2B5B BB14 3BA0 B290 DCEE 6668 B798 AE89 9087 7201"),
         ('is_expired',    False),
         ('is_primary',    True),
         ('is_protected',  True),
         ('is_public',     False),
         ('is_unlocked',   False),
         ('key_algorithm', PubKeyAlgorithm.DSA),],

    'tests/testdata/blocks/dsapubkey.asc':
        [('created',       datetime(2017, 2, 21, 19, 21, 41, tzinfo=timezone.utc)),
         ('expires_at',    None),
         ('fingerprint',   "2B5B BB14 3BA0 B290 DCEE 6668 B798 AE89 9087 7201"),
         ('is_expired',    False),
         ('is_primary',    True),
         ('is_protected',  False),
         ('is_public',     True),
         ('is_unlocked',   True),
         ('key_algorithm', PubKeyAlgorithm.DSA),],

    'tests/testdata/blocks/openpgp.js.pubkey.asc':
        [('created',        datetime(2016, 6, 2, 21, 57, 13, tzinfo=timezone.utc)),
         ('expires_at',     None),
         ('fingerprint',    "C7C3 8ECE E94A 4AD3 2DDB  064E 14AB 44C7 4D1B DAB8"),
         ('is_expired',     False),
         ('is_primary',     True),
         ('is_protected',   False),
         ('is_public',      True),
         ('is_unlocked',    True),
         ('key_algorithm',  PubKeyAlgorithm.RSAEncryptOrSign),
         ('magic',          "PUBLIC KEY BLOCK"),
         ('parent',         None),
         ('signers',        set()), ],

    'tests/testdata/blocks/openpgp.js.seckey.asc':
        [('created',        datetime(2016, 6, 2, 21, 57, 13, tzinfo=timezone.utc)),
         ('expires_at',     None),
         ('fingerprint',    "C7C3 8ECE E94A 4AD3 2DDB  064E 14AB 44C7 4D1B DAB8"),
         ('is_expired',     False),
         ('is_primary',     True),
         ('is_protected',   False),
         ('is_public',      False),
         ('is_unlocked',    True),
         ('key_algorithm',  PubKeyAlgorithm.RSAEncryptOrSign),
         ('magic',          "PRIVATE KEY BLOCK"),
         ('parent',         None),
         ('signers',        set()), ],

    'tests/testdata/blocks/signature.expired.asc':
        [('created',       datetime(2014, 9, 28, 20, 54, 42, tzinfo=timezone.utc)),
         ('is_expired',    True),],

    'tests/testdata/blocks/signature.non-exportable.asc':
        [('created',       datetime(2017, 2, 21, 20, 43, 34, tzinfo=timezone.utc)),
         ('exportable',    False),]
}


# generic block tests
class TestBlocks(object):
    @pytest.mark.parametrize('block', blocks, ids=[os.path.basename(f) for f in blocks])
    def test_load_blob(self, block):
        with open(block) as bf:
            bc = bf.read()

        if 'SIGNATURE' in bc.splitlines()[0]:
            p = PGPSignature()

        elif 'KEY' in bc.splitlines()[0]:
            p = PGPKey()

        elif 'MESSAGE' in bc.splitlines()[0]:
            p = PGPMessage()

        else:
            pytest.skip("not ready for file '{}'".format(os.path.basename(block)))
            assert False

        # load ASCII
        p.parse(bc)

        # check str output
        # assert str(p) == bc

        # now check attrs
        assert block in block_attrs
        for attr, val in block_attrs[block]:
            attrval = getattr(p, attr)
            # this is probably more helpful than just 'assert attrval == val'
            if attrval != val:
                raise AssertionError('expected block.{attr:s} = {aval}; got block.{attr:s} = {rval}'
                                     ''.format(attr=attr, aval=val, rval=attrval))


armored = glob.glob('tests/testdata/*/*.asc')
txt = glob.glob('tests/testdata/files/*.txt')
binary = glob.glob('tests/testdata/files/*.bin')
raw = txt + binary

# armor matching test
class TestMatching(object):
    @pytest.mark.parametrize('armored', armored, ids=[os.path.basename(f) for f in armored])
    def test_is_armor(self, armored):
        with open(armored) as af:
            ac = af.read()

        assert Armorable.is_armor(ac)

    @pytest.mark.parametrize('text', raw, ids=[os.path.basename(f) for f in raw])
    def test_not_armor(self, text):
        mode = 'r' if text in txt else 'rb'
        with open(text, mode) as tf:
            tc = tf.read()

        assert not Armorable.is_armor(tc)
