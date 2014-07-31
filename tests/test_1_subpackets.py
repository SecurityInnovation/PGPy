""" test subpacket parsing
"""
import pytest

import os
import re


# from pgpy.packet.subpackets.types import Signature

from pgpy.packet.subpackets import Signature
from pgpy.packet.subpackets import UserAttribute

from pgpy.packet.subpackets.types import Header
from pgpy.packet.subpackets.types import Opaque

# from pgpy.packet.subpackets.signature import CreationTime

spdir = 'tests/testdata/subpackets/'

def pytest_generate_tests(metafunc):
    tdata = []

    if 'subpacket' in metafunc.fixturenames:
        if metafunc.cls is TestSignatureSubPackets:
            tdata = sorted([ spdir + f for f in os.listdir(spdir) if 'signature' in f ])

        if metafunc.cls is TestUserAttributeSubPackets:
            tdata = sorted([ spdir + f for f in os.listdir(spdir) if 'userattr' in f ])

        # argvals = [ open(sp, 'rb').read() for sp in tdata ]
        argvals = [bytearray(os.path.getsize(sp)) for sp in tdata]
        for i, spf in enumerate(tdata):
            with open(spf, 'rb') as sp:
                sp.readinto(argvals[i])
        ids = [ re.split('\.0x', sp)[1] for sp in tdata ]

        metafunc.parametrize('subpacket', argvals, ids=ids, scope="class")


# class SPFixture(object):
#     def __init__(self, b):
#         self._bytes = b
#         self._subpacket = None
_sspclasses = {
    # 0x00: 'Opaque',
    # 0x01: 'Opaque',
    0x02: 'CreationTime',
    0x03: 'SignatureExpirationTime',
    0x04: 'ExportableCertification',
    0x05: 'TrustSignature',
    0x06: 'RegularExpression',
    0x07: 'Revocable',
    # 0x08: 'Opaque',
    0x09: 'KeyExpirationTime',
    # 0x0a: 'Opaque',
    0x0b: 'PreferredSymmetricAlgorithms',
    0x0c: 'RevocationKey',
    # 0x0d: 'Opaque',
    # 0x0e: 'Opaque',
    # 0x0f: 'Opaque',
    0x10: 'Issuer',
    # 0x11: 'Opaque',
    # 0x12: 'Opaque',
    # 0x13: 'Opaque',
    0x14: 'NotationData',
    0x15: 'PreferredHashAlgorithms',
    0x16: 'PreferredCompressionAlgorithms',
    0x17: 'KeyServerPreferences',
    0x18: 'PreferredKeyServer',
    0x19: 'PrimaryUserID',
    0x1a: 'Policy',
    0x1b: 'KeyFlags',
    0x1c: 'SignersUserID',
    0x1d: 'ReasonForRevocation',
    0x1e: 'Features',
    0x1f: 'Target',  ##TODO: obtain one of these
    # 0x20: 'EmbeddedSignature' ##TODO: parse this, then uncomment
    # 0x64-0x6e: Private or Experimental ##TODO: figure out how to parse the 0x65 packet I found
}

_sspdump = {
    # 0x00: 'Opaque',
    # 0x01: 'Opaque',
    0x02: 'Sub: signature creation time(sub 2)(4 bytes)\n'
          '\t\tTime - Wed Oct  1 15:47:31 UTC 2003\n',
    0x03: 'Sub: signature expiration time(sub 3)(4 bytes)\n'
          '\t\tTime - Thu Jan 15 00:00:00 UTC 1970\n',
    # 0x04: 'ExportableCertification',
    0x05: 'Sub: trust signature(sub 5)(2 bytes)\n'
          '\t\tLevel - 01\n'
          '\t\tAmount - 78\n',
    0x06: 'Sub: regular expression(sub 6)(28 bytes)\n'
          '\t\tRegex - <[^>]+[@.]liebenzell\.org>$\n',
    0x07: 'Sub: revocable(sub 7)(1 bytes)\n'
          '\t\tRevocable - No\n',
    # 0x08: 'Opaque',
    0x09: 'Sub: key expiration time(sub 9)(4 bytes)\n'
          '\t\tTime - Fri Jan  1 00:00:00 UTC 1971\n',
    # 0x0a: 'Opaque',
    0x0b: 'Sub: preferred hash algorithms(sub 11)(4 bytes)\n'
          '\t\tSym alg - AES with 128-bit key(sym 7)\n'
          '\t\tSym alg - Twofish with 256-bit key(sym 10)\n'
          '\t\tSym alg - CAST5(sym 3)\n'
          '\t\tSym alg - Blowfish(sym 4)\n',
    # 0x0c: 'RevocationKey',
    # 0x0d: 'Opaque',
    # 0x0e: 'Opaque',
    # 0x0f: 'Opaque',
    # 0x10: 'Issuer',
    # 0x11: 'Opaque',
    # 0x12: 'Opaque',
    # 0x13: 'Opaque',
    # 0x14: 'NotationData',
    # 0x15: 'PreferredHashAlgorithms',
    # 0x16: 'PreferredCompressionAlgorithms',
    # 0x17: 'KeyServerPreferences',
    # 0x18: 'PreferredKeyServer',
    # 0x19: 'PrimaryUserID',
    # 0x1a: 'Policy',
    # 0x1b: 'KeyFlags',
    # 0x1c: 'SignersUserID',
    # 0x1d: 'ReasonForRevocation',
    # 0x1e: 'Features',
    # 0x1f: 'Target',  ##TODO: obtain one of these
    # 0x20: 'EmbeddedSignature' ##TODO: parse this, then uncomment
    # 0x64-0x6e: Private or Experimental ##TODO: figure out how to parse the 0x65 packet I found
}

_uaspclasses = {
    0x01: 'Image'
}


class TestSignatureSubPackets(object):
    @pytest.mark.parametrize('b',
        [ bytearray(b'\xbf'                 + b'\x00' + (b'\x00' * 190)),    # 1 byte length - 191
          bytearray(b'\xc0\x00'             + b'\x00' + (b'\x00' * 191)),    # 2 byte length - 192
          bytearray(b'\xdf\xff'             + b'\x00' + (b'\x00' * 8382)),   # 2 byte length - 8383
          bytearray(b'\xff\x00\x00 \xc0'    + b'\x00' + (b'\x00' * 0x8383)), # 5 byte length - 8384
          bytearray(b'\xff\x00\x00\xff\xff' + b'\x00' + (b'\x00' * 65534))   # 5 byte length - 65535
        ])
    def test_header(self, b):
        h = Header()
        # h._bytes = lambda: memoryview(b).__enter__()[:h._len]
        h.parse(b)

        assert 65537 > h.length > 1
        assert len(h) == len(bytes(h))

    def test_load(self, subpacket):
        sp = Signature(bytearray(subpacket))

        assert len(sp) == len(subpacket)
        assert len(sp) == len(bytes(sp))
        assert bytes(sp) == bytes(subpacket)

        if sp.header.typeid in _sspclasses:
            assert sp.__class__.__name__ == _sspclasses[sp.header.typeid]

        else:
            assert isinstance(sp, Opaque)


class TestUserAttributeSubPackets(object):
    def test_load(self, subpacket):
        sp = UserAttribute(bytearray(subpacket))

        assert len(sp) == len(subpacket)
        assert len(sp) == len(bytes(sp))
        assert bytes(sp) == bytes(subpacket)

        if sp.header.typeid in _uaspclasses:
            assert sp.__class__.__name__ == _uaspclasses[sp.header.typeid]

        else:
            assert isinstance(sp, Opaque)