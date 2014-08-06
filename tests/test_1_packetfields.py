""" test subpacket parsing
"""
import pytest

from itertools import product

from pgpy.constants import HashAlgorithm
from pgpy.constants import String2KeyType
from pgpy.constants import SymmetricKeyAlgorithm

from pgpy.packet.types import Header
from pgpy.packet.fields import String2Key

from pgpy.packet.subpackets import Signature
from pgpy.packet.subpackets import UserAttribute

from pgpy.packet.subpackets.types import Header as HeaderSP
from pgpy.packet.subpackets.types import Opaque as OpaqueSP


class TestHeaders(object):
    def test_subpacket_header(self, spheader):
        h = HeaderSP()
        h.parse(spheader)

        assert 65537 > h.length > 1
        assert len(h) == len(bytes(h))

    def test_packet_header(self, pheader):
        b = pheader[:]
        h = Header()
        h.parse(pheader)

        assert h.tag == 0x02
        assert h.length == len(pheader)
        assert len(h) == len(b) - len(pheader)
        assert bytes(h) == b[:len(h)]

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
    def test_load(self, sigsubpacket):
        spb = sigsubpacket[:]
        sp = Signature(sigsubpacket)

        assert len(sigsubpacket) == 0
        assert len(sp) == len(spb)
        assert len(sp) == len(bytes(sp))
        assert bytes(sp) == bytes(spb)

        if sp.header.typeid in _sspclasses:
            assert sp.__class__.__name__ == _sspclasses[sp.header.typeid]

        else:
            assert isinstance(sp, OpaqueSP)


class TestUserAttributeSubPackets(object):
    def test_load(self, uasubpacket):
        sp = UserAttribute(bytearray(uasubpacket))

        assert len(sp) == len(uasubpacket)
        assert len(sp) == len(bytes(sp))
        assert bytes(sp) == bytes(uasubpacket)

        if sp.header.typeid in _uaspclasses:
            assert sp.__class__.__name__ == _uaspclasses[sp.header.typeid]

        else:
            assert isinstance(sp, OpaqueSP)


class TestString2Key(object):
    @pytest.mark.parametrize('b',
        [ (bytearray(i) +
           b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF') # iv
          for i in product(b'\xff',                                         # usage
                           b'\x01\x02\x03\x04\x07\x08\x09\x0B\x0C\x0D',     # symmetric cipher algorithm
                           b'\x00',                                         # specifier (simple)
                           b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B') # hash algorithm
        ])
    def test_simple_string2key(self, b):
        _b = b[:]
        s = String2Key()
        s.parse(b)

        assert len(b) == 0
        assert len(s) == len(_b)
        assert bytes(s) == bytes(_b)

        assert bool(s)
        assert s.halg in HashAlgorithm
        assert s.encalg in SymmetricKeyAlgorithm
        assert s.specifier == String2KeyType.Simple
        assert s.iv == b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'

    @pytest.mark.parametrize('b',
        [ (bytearray(i) +
           b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE' + # salt
           b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF')  # iv
          for i in product(b'\xff',                                         # usage
                           b'\x01\x02\x03\x04\x07\x08\x09\x0B\x0C\x0D',     # symmetric cipher algorithm
                           b'\x01',                                         # specifier (salted)
                           b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B') # hash algorithm

        ])
    def test_salted_string2key(self, b):
        _b = b[:]
        s = String2Key()
        s.parse(b)

        assert len(b) == 0
        assert len(s) == len(_b)
        assert bytes(s) == bytes(_b)

        assert bool(s)
        assert s.halg in HashAlgorithm
        assert s.encalg in SymmetricKeyAlgorithm
        assert s.specifier == String2KeyType.Salted
        assert s.salt == b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE'
        assert s.iv == b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'

    @pytest.mark.parametrize('b',
        [ (bytearray(i) +
           b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE' + # salt
           b'\x10' +                             # count
           b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF')  # iv
          for i in product(b'\xff',                                         # usage
                           b'\x01\x02\x03\x04\x07\x08\x09\x0A\x0B\x0C\x0D', # symmetric cipher algorithm
                           b'\x03',                                         # specifier (iterated)
                           b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B') # hash algorithm

        ])
    def test_iterated_string2key(self, b):
        _b = b[:]
        s = String2Key()
        s.parse(b)

        assert len(b) == 0
        assert len(s) == len(_b)
        assert bytes(s) == bytes(_b)

        assert bool(s)
        assert s.halg in HashAlgorithm
        assert s.encalg in SymmetricKeyAlgorithm
        assert s.specifier == String2KeyType.Iterated
        assert s.salt == b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE'
        assert s.count == 2048
        assert s.iv == b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
