# coding=utf-8
""" Testing different versions of public keys across different versions of packets
"""

from typing import Dict, NamedTuple, Optional, Tuple

import pytest

from warnings import warn

from itertools import product
from datetime import datetime, timezone

from pgpy import PGPKey, PGPSignature, PGPMessage, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm, Features
from pgpy.errors import PGPDecryptionError


class KeyDescriptor(NamedTuple):
    primary_alg: PubKeyAlgorithm
    subkey_alg: PubKeyAlgorithm
    key_version: int
    features: Features

    @property
    def key_and_cert(self) -> Tuple[PGPKey, PGPKey]:
        'cache the created keys to be able to reuse them cleanly'
        if self not in kd_instances:
            if (self.primary_alg, self.key_version) not in kd_primary_keys:
                kd_primary_keys[(self.primary_alg, self.key_version)] = PGPKey.new(self.primary_alg, version=self.key_version, created=creation_time)
            key = kd_primary_keys[(self.primary_alg, self.key_version)]
            prefs = {
                'usage': KeyFlags.Certify | KeyFlags.Sign,
                'hashes': [
                    HashAlgorithm.SHA3_512,
                    HashAlgorithm.SHA3_256,
                    HashAlgorithm.SHA512,
                    HashAlgorithm.SHA256
                ],
                'ciphers': [SymmetricKeyAlgorithm.AES256,
                            SymmetricKeyAlgorithm.AES128],
                'compression': [CompressionAlgorithm.Uncompressed],
                'features': self.features,
            }
            key |= key.certify(key, **prefs)
            if self.key_version == 4:
                key.add_uid(PGPUID.new('Example User <user@example.org>'), selfsign=True, **prefs)
            if (self.subkey_alg, self.key_version) not in kd_subkeys:
                kd_subkeys[(self.subkey_alg, self.key_version)] = PGPKey.new(self.subkey_alg, version=self.key_version, created=creation_time)
            key.add_subkey(kd_subkeys[(self.subkey_alg, self.key_version)],
                           usage=KeyFlags.EncryptCommunications | KeyFlags.EncryptStorage)
            cert = key.pubkey
            kd_instances[self] = (key, cert)
        return kd_instances[self]

    def __repr__(self) -> str:
        return f"v{self.key_version} {self.primary_alg.name},{self.subkey_alg.name} {self.features!r}"

kdescs = list(KeyDescriptor(*x) for x in product(list(filter(lambda x: x.can_sign and x.can_gen, PubKeyAlgorithm)),
                                                 list(filter(lambda x: x.can_encrypt and x.can_gen, PubKeyAlgorithm)),
                                                 [4,6],
                                                 [Features.SEIPDv1, Features.SEIPDv1 | Features.SEIPDv2]
                                                 ))

creation_time = datetime.now(tz=timezone.utc)

kd_primary_keys: Dict[Tuple[PubKeyAlgorithm, int], PGPKey] = {}
kd_subkeys: Dict[Tuple[PubKeyAlgorithm, int], PGPKey] = {}
kd_instances: Dict[KeyDescriptor, Tuple[PGPKey, PGPKey]] = {}

class TestPGP_Version_Pubkey(object):
    @pytest.mark.parametrize('kdesc', kdescs, ids=list(map(repr, kdescs)))
    def test_encrypt_decrypt_roundtrip(self, kdesc: KeyDescriptor) -> None:
        key, cert = kdesc.key_and_cert
        msg = PGPMessage.new('this is a test', compression=CompressionAlgorithm.Uncompressed)

        encmsg = cert.encrypt(msg)
        encmsg2 = PGPMessage.from_blob(bytes(encmsg))
        newmsg = key.decrypt(encmsg2)
        assert newmsg.message == msg.message

    @pytest.mark.parametrize('kdesc', kdescs, ids=list(map(repr, kdescs)))
    def test_sign_verify_roundtrip(self, kdesc: KeyDescriptor) -> None:
        key, cert = kdesc.key_and_cert

        msg = 'this is a test'
        sig = key.sign(msg)
        sig2 = PGPSignature.from_blob(bytes(sig))
        assert cert.verify(msg, sig2)
