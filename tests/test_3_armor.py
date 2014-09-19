""" test (de)armoring of PGP blocks
"""
import pytest

import glob

from datetime import datetime

from pgpy.constants import CompressionAlgorithm
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SignatureType
from pgpy.constants import SymmetricKeyAlgorithm

from pgpy.pgp import PGPKey
from pgpy.pgp import PGPMessage
from pgpy.pgp import PGPSignature


# generic block tests
class TestBlocks(object):
    params = {
        'block': glob.glob('tests/testdata/blocks/*.asc')
    }
    attrs = {
        'tests/testdata/blocks/message.compressed.asc':
            [('encrypters',    set()),
             ('issuers',       set()),
             ('signers',       set()),
             ('is_compressed', True),
             ('is_encrypted',  False),
             ('is_signed',     False),
             ('type',          'compressed'),
             ('message',       b"This is stored, literally\\!\n\n")],
        'tests/testdata/blocks/message.literal.asc':
            [('encrypters',    set()),
             ('issuers',       set()),
             ('signers',       set()),
             ('is_compressed', False),
             ('is_encrypted',  False),
             ('is_signed',     False),
             ('type',          'literal'),
             ('message',       b"This is stored, literally\\!\n\n")],
        'tests/testdata/blocks/message.onepass.asc':
            [('encrypters',    set()),
             ('issuers',       {'2A834D8E5918E886'}),
             ('signers',       {'2A834D8E5918E886'}),
             ('is_compressed', False),
             ('is_encrypted',  False),
             ('is_signed',     True),
             ('type',          'signed'),
             ('message',       b"This is stored, literally\\!\n\n")],
        'tests/testdata/blocks/message.two_onepass.asc':
            [('encrypters',    set()),
             ('issuers',       {'2A834D8E5918E886', 'A5DCDC966453140E'}),
             ('signers',       {'2A834D8E5918E886', 'A5DCDC966453140E'}),
             ('is_compressed', False),
             ('is_encrypted',  False),
             ('is_signed',     True),
             ('type',          'signed'),
             ('message',       b"This is stored, literally\\!\n\n")],
        'tests/testdata/blocks/message.signed.asc':
            [('encrypters',    set()),
             ('issuers',       {'2A834D8E5918E886'}),
             ('signers',       {'2A834D8E5918E886'}),
             ('is_compressed', False),
             ('is_encrypted',  False),
             ('is_signed',     True),
             ('type',         'signed'),
             ('message',      b"This is stored, literally\\!\n\n")],
        'tests/testdata/blocks/cleartext.asc':
            [('encrypters',    set()),
             ('issuers',       {'2A834D8E5918E886'}),
             ('signers',       {'2A834D8E5918E886'}),
             ('is_compressed', False),
             ('is_encrypted',  False),
             ('is_signed',     True),
             ('type',          'cleartext'),
             ('message',       "This is stored, literally\\!\n")],
        'tests/testdata/blocks/cleartext.twosigs.asc':
            [('encrypters',    set()),
             ('issuers',       {'2A834D8E5918E886', 'A5DCDC966453140E'}),
             ('signers',       {'2A834D8E5918E886', 'A5DCDC966453140E'}),
             ('is_compressed', False),
             ('is_encrypted',  False),
             ('is_signed',     True),
             ('type',          'cleartext'),
             ('message',       "This is stored, literally\\!\n")],
        'tests/testdata/blocks/message.encrypted.asc':
            [('encrypters',    {'EEE097A017B979CA'}),
             ('issuers',       {'EEE097A017B979CA'}),
             ('signers',       set()),
             ('is_compressed', False),
             ('is_encrypted',  True),
             ('is_signed',     False),
             ('type',         'encrypted')],
        'tests/testdata/blocks/message.encrypted.signed.asc':
            [('encrypters',    {'EEE097A017B979CA'}),
             ('issuers',       {'EEE097A017B979CA'}),
             ('signers',       set()),
             ('is_compressed', False),
             ('is_encrypted',  True),
             ('is_signed',     False),
             ('type',         'encrypted')],
        'tests/testdata/blocks/rsapubkey.asc':
            [('fingerprint', "F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36"),
             ('magic',       "PUBLIC KEY BLOCK"),
             ('parent',      None),
             ('cipherprefs', [SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128]),
             ('compprefs',   [CompressionAlgorithm.ZLIB]),
             ('hashprefs',   [HashAlgorithm.SHA256]),
             ('usageflags',  [KeyFlags.Certify])],
        'tests/testdata/blocks/rsaseckey.asc':
            [('fingerprint', "F429 4BC8 094A 7E05 85C8 5E86 3747 3B37 58C4 4F36"),
             ('magic',       "PRIVATE KEY BLOCK"),
             ('parent',      None),
             ('cipherprefs', [SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128,
                              SymmetricKeyAlgorithm.CAST5, SymmetricKeyAlgorithm.TripleDES]),
             ('compprefs',   [CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP]),
             ('hashprefs',   [HashAlgorithm.SHA256, HashAlgorithm.SHA1, HashAlgorithm.SHA384, HashAlgorithm.SHA512,
                              HashAlgorithm.SHA224]),
             ('usageflags',  [KeyFlags.Certify])],
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
            ('created',        datetime.utcfromtimestamp(1402615373)),
            ('embedded',       False),
            ('expired',        False),
            ('exportable',     True),
            ('features',       []),
            ('hash2',          b'\xc4\x24'),
            ('hashprefs',      []),
            ('hash_algorithm', HashAlgorithm.SHA512),
            ('key_algorithm',  PubKeyAlgorithm.RSAEncryptOrSign),
            ('key_flags',      []),
            ('keyserver',      ''),
            ('keyserverprefs', []),
            ('magic',          "SIGNATURE"),
            ('notation',       {}),
            ('revocable',      True),
            ('revocation_key', None),
            ('signer',         'FCAE54F74BA27CF7'),
            ('type',           SignatureType.BinaryDocument)]
    }
    def test_load(self, block):
        with open(block) as bf:
            bc = bf.read()

        if 'SIGNATURE' in bc.splitlines()[0]:
            p = PGPSignature()

        elif 'KEY' in bc.splitlines()[0]:
            p = PGPKey()


        elif 'MESSAGE' in bc.splitlines()[0]:
            p = PGPMessage()

        else:
            pytest.skip("not ready for this one")
            assert False

        # load ASCII
        p.parse(bc)

        # now check attrs
        assert block in self.attrs
        for attr, val in self.attrs[block]:
            assert getattr(p, attr) == val
