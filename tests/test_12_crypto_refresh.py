# coding=utf-8
""" Verify samples from draft-ietf-openpgp-crypto-refresh-10
"""

from typing import Dict, Optional, Tuple
from types import ModuleType

import pytest

from warnings import warn

from pgpy import PGPKey, PGPSignature, PGPMessage
from pgpy.errors import PGPDecryptionError

Cryptodome:Optional[ModuleType]
try:
    import Cryptodome
except ModuleNotFoundError:
    Cryptodome = None

class TestPGP_CryptoRefresh(object):
    def test_v4_sigs(self) -> None:
        (k, _) = PGPKey.from_file('tests/testdata/crypto-refresh/v4-ed25519-pubkey-packet.key')
        s = PGPSignature.from_file('tests/testdata/crypto-refresh/v4-ed25519-signature-over-OpenPGP.sig')
        assert k.verify('OpenPGP', s)
        assert not k.verify('Banana', s)

    @pytest.mark.parametrize('cipher', {'aes128', 'aes192', 'aes256'})
    def test_v4_skesk_argon2(self, cipher: str) -> None:
        msg = PGPMessage.from_file(f'tests/testdata/crypto-refresh/v4skesk-argon2-{cipher}.pgp')
        assert msg.is_encrypted
        unlocked = msg.decrypt('password')
        assert not unlocked.is_encrypted
        assert unlocked.message == b'Hello, world!'

    @pytest.mark.parametrize('aead', {'ocb', 'eax', 'gcm'})
    def test_v6_skesk(self, aead: str) -> None:
        msg = PGPMessage.from_file(f'tests/testdata/crypto-refresh/v6skesk-aes128-{aead}.pgp')
        assert msg.is_encrypted
        if aead == 'eax' and Cryptodome is None:
            pytest.xfail('AEAD Mode EAX is not supported unless the Cryptodome module is available')
        unlocked = msg.decrypt('password')
        assert not unlocked.is_encrypted
        assert unlocked.message == b'Hello, world!'

    @pytest.mark.parametrize('msg', {'inline-signed-message.pgp', 'cleartext-signed-message.txt'})
    def test_v6_signed_messages(self, msg: str) -> None:
        (cert, _) = PGPKey.from_file('tests/testdata/crypto-refresh/v6-minimal-cert.key')
        assert cert.is_public
        pgpmsg = PGPMessage.from_file(f'tests/testdata/crypto-refresh/{msg}')
        assert not pgpmsg.is_encrypted
        assert pgpmsg.message == 'What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n'
        assert cert.verify(pgpmsg)

    def test_v6_key(self):
        (cert, _) = PGPKey.from_file('tests/testdata/crypto-refresh/v6-minimal-cert.key')
        assert cert.is_public
        (key, _) = PGPKey.from_file('tests/testdata/crypto-refresh/v6-minimal-secret.key')
        assert not key.is_public
        assert not key.is_protected
        assert key.is_unlocked
        msg = PGPMessage.from_file('tests/testdata/crypto-refresh/v6pkesk-aes128-ocb.pgp')
        assert msg.is_encrypted
        clearmsg = key.decrypt(msg)
        assert not clearmsg.is_encrypted
        assert clearmsg.message == b'Hello, world!'

        # verify decryption with unprotected key
        (locked, _) = PGPKey.from_file('tests/testdata/crypto-refresh/v6-minimal-secret-locked.key')
        assert not locked.is_public
        assert locked.is_protected
        assert not locked.is_unlocked
        with locked.unlock("correct horse battery staple"):
            assert locked.is_unlocked
            clearmsg2 = locked.decrypt(msg)
            assert not clearmsg2.is_encrypted
            assert clearmsg2.message == b'Hello, world!'
