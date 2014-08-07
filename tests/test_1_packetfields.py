""" test field parsing
"""
import pytest

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
        assert h.length == len(pheader) - 4
        assert pheader[h.length:] == b'\xca\xfe\xba\xbe'
        assert len(h) == len(b) - len(pheader)
        assert bytes(h) == b[:len(h)]

_sspclasses = {
    # 0x00: 'Opaque',
    # 0x01: 'Opaque',
    0x02: 'CreationTime',
    0x03: 'SignatureExpirationTime',
    # 0x04: 'ExportableCertification',  ##TODO: obtain one of these
    0x05: 'TrustSignature',
    0x06: 'RegularExpression',
    0x07: 'Revocable',
    # 0x08: 'Opaque',
    0x09: 'KeyExpirationTime',
    # 0x0a: 'AdditionalDecryptionKey',  ##TODO: parse this, then uncomment
    0x0b: 'PreferredSymmetricAlgorithms',
    0x0c: 'RevocationKey',
    # 0x0d: 'Opaque',
    # 0x0e: 'Opaque',
    # 0x0f: 'Opaque',
    0x10: 'Issuer',
    # 0x11: 'Opaque',
    0x12: 'Opaque',  # reserved
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
    # 0x1f: 'Target',  ##TODO: obtain one of these ##TODO: parse this, then uncomment
    # 0x20: 'EmbeddedSignature' ##TODO: parse this, then uncomment
    # 0x64-0x6e: Private or Experimental
    0x64: 'Opaque',
    0x65: 'Opaque',
    0x66: 'Opaque',
    0x67: 'Opaque',
    0x68: 'Opaque',
    0x69: 'Opaque',
    0x6a: 'Opaque',
    0x6b: 'Opaque',
    0x6c: 'Opaque',
    0x6d: 'Opaque',
    0x6e: 'Opaque',
}

_sspdump = {
    # 0x00: 'Opaque',
    # 0x01: 'Opaque',
    0x02: 'Sub: signature creation time(sub 2)(4 bytes)\n'
          '\t\tTime - Wed Oct  1 15:47:31 UTC 2003\n',
    0x03: 'Sub: signature expiration time(sub 3)(4 bytes)\n'
          '\t\tTime - Thu Jan 15 00:00:00 UTC 1970\n',
    #     '\t\tTime - Wed Oct 15 08:47:31 PDT 2003\n', # <- this is the real time
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
    0x0a: 'Sub: additional decryption key(sub 10) WARNING: see CA-2000-18!!!(22 bytes)\n'
          '\t\tClass - Normal\n'
          '\t\tPub alg - DSA Digital Signature Algorithm(pub 17)\n'
          '\t\tFingerprint - 4d 2c 9e 2c ee 7e 26 0d 4b bd 9b 5b 1b 60 bc 75 0c ef 57 06\n',
    0x0b: 'Sub: preferred hash algorithms(sub 11)(4 bytes)\n'
          '\t\tSym alg - AES with 128-bit key(sym 7)\n'
          '\t\tSym alg - Twofish with 256-bit key(sym 10)\n'
          '\t\tSym alg - CAST5(sym 3)\n'
          '\t\tSym alg - Blowfish(sym 4)\n',
    0x0c: 'Sub: revocation key(sub 12)(22 bytes)\n'
          '\t\tClass - Normal\n'
          '\t\tPub alg - DSA Digital Signature Algorithm(pub 17)\n'
          '\t\tFingerprint - 39 06 f8 f6 98 64 9e be 50 47 d0 ba 11 ed a7 d0 21 3c a1 1b\n',
    # 0x0d: 'Opaque',
    # 0x0e: 'Opaque',
    # 0x0f: 'Opaque',
    0x10: 'Sub: issuer key ID(sub 16)(8 bytes)\n'
          '\t\tKey ID - 0x0A275AB6B4BCA5D7\n',
    # 0x11: 'Opaque',
    0x12: 'Sub: reserved(sub 18)(4 bytes)\n',
    # 0x13: 'Opaque',
    0x14: 'Sub: notation data(sub 20)(134 bytes)\n'
          '\t\tFlag - Human-readable\n'
          '\t\tName - signotes@grep.be\n'
          '\t\tValue - "http://www.grep.be/gpg/CF62318D5BBED48F33ACD5431B0006256FB29164/0138DA92EDFFB27DD270F86DB475E207BAB58229.asc"\n',
    0x15: 'Sub: referred hash algorithms(sub 21)(2 bytes)\n'
          '\t\tHash alg - RIPEMD160(hash 3)\n'
          '\t\tHash alg - SHA1(hash 2)',
    0x16: 'Sub: preferred compression algorithms(sub 22)(2 bytes)\n'
          '\t\tComp alg - ZLIB <RFC1950>(comp 2)\n'
          '\t\tComp alg - ZIP <RFC1951>(comp 1)\n',
    0x17: 'Sub: key server preferences(sub 23)(1 bytes)\n'
          '\t\tFlag - No-modify\n',
    0x18: 'Sub: preferred key server(sub 24)(24 bytes)\n'
          '\t\tURL - hkp://fakekey.server.tld\n',
    0x19: 'Sub: primary User ID(sub 25)(1 bytes)\n'
          '\t\tPrimary - Yes\n',
    0x1a: 'Sub: policy URL(sub 26)(20 bytes)\n'
          '\t\tURL - http://www.blaap.org\n',
    0x1b: 'Sub: key flags(sub 27)(1 bytes)\n'
          '\t\tFlag - This key may be used to certify other keys\n'
          '\t\tFlag - This key may be used to sign data\n'
          '\t\tFlag - This key may be used for authentication\n',
    0x1c: 'Sub: signer\'s User ID(sub 28)(31 bytes)\n'
          '\t\tUser ID - Sander Temme <sander@temme.net>\n',
    0x1d: 'Sub: reason for revocation(sub 29)(1 bytes)\n'
          '\t\tReason - No reason specified\n'
          '\t\tComment - \n',
    0x1e: 'Sub: features(sub 30)(1 bytes)\n'
          '\t\tFlag - Modification detection (packets 18 and 19)\n',
    # 0x1f: 'Target',  ##TODO: obtain one of these
    0x20: 'Sub: embedded signature(sub 32)(284 bytes)\n'
          '\tVer 4 - new\n'
          '\tSig type - Primary Key Binding Signature(0x19).\n'
          '\tPub alg - RSA Encrypt or Sign(pub 1)\n'
          '\tHash alg - SHA512(hash 10)\n'
          '\tHashed Sub: signature creation time(sub 2)(4 bytes)\n'
          '\t\tTime - Thu Jun 12 23:21:42 UTC 2014\n'
          '\tSub: issuer key ID(sub 16)(8 bytes)\n'
          '\t\tKey ID - 0x1971F7B88067DD07\n'
          '\tHash left 2 bytes - d2 30 \n'
          '\tRSA m^d mod n(2045 bits) - 19 bb ea 3b 36 7c db 31 f3 bc fb 5a 1d b6 cf 59 e6 26 e9 ed f1 4f dc 84 dd '
          'e1 88 ff b9 ba 1a e9 8d 16 4b d2 b4 f4 39 7f 28 c9 e8 2f f6 87 0f ef b7 2a f9 27 72 7b 45 f3 07 3f cb ff '
          '6d 87 86 26 48 ee c4 bc f1 4c 17 37 92 db f9 49 16 51 f6 9e 69 f5 36 7a 0f ff 5e 92 88 4b 68 bd 3b 20 86 '
          'a5 ba 4c a2 da 93 ae 10 d1 59 a5 a7 b4 29 2a f6 a1 2c 5d d1 e3 5c c3 6c 33 ec 41 ec 26 14 35 e1 c4 d0 15 '
          '79 b2 f8 0c 0e d3 5f 5b 1f 0f 4d 98 a8 4a b3 d9 3f a4 b3 16 ee 38 ad 2f 07 ea 7f ad 1a 0f be 06 94 a5 31 '
          'f6 40 ae cd 79 92 42 1c d5 04 7a bf e9 bc 9c ac 99 57 36 81 ad e0 81 b4 89 6e d0 5f 1c 92 be f6 1c 6d 6e '
          'e9 32 5f 86 cf b0 76 1f 9d 6b 25 bd 3c 0c 1e 91 0c ec 5c dc 8c 43 75 d8 4e f2 82 45 00 c8 72 6e 53 59 1b '
          'a0 25 13 c0 24 51 2b d3 d0 d8 20 0c e9 af 49 35 26 e5 c1 21 af \n'
          '\t\t-> PKCS-1\n',
    # 0x64: '',  # 0x64-0x6e: Private or Experimental
    0x65: '\tHashed Sub: unknown(sub 101)(6 bytes)\n',
    # 0x66: '',  # 0x64-0x6e: Private or Experimental
    # 0x67: '',  # 0x64-0x6e: Private or Experimental
    # 0x68: '',  # 0x64-0x6e: Private or Experimental
    # 0x69: '',  # 0x64-0x6e: Private or Experimental
    # 0x6a: '',  # 0x64-0x6e: Private or Experimental
    # 0x6b: '',  # 0x64-0x6e: Private or Experimental
    # 0x6c: '',  # 0x64-0x6e: Private or Experimental
    # 0x6d: '',  # 0x64-0x6e: Private or Experimental
    # 0x6e: '',  # 0x64-0x6e: Private or Experimental
}
_uaspclasses = {
    0x01: 'Image'
}


class TestSignatureSubPackets(object):
    def test_load(self, sigsubpacket):
        spb = sigsubpacket[:]
        sp = Signature(sigsubpacket)

        assert sigsubpacket == b'\xca\xfe\xba\xbe'
        assert len(sp) == len(spb) - 4
        assert len(sp) == len(bytes(sp))
        assert bytes(sp) == bytes(spb[:-4])

        if sp.header.typeid in _sspclasses:
            assert sp.__class__.__name__ == _sspclasses[sp.header.typeid]

        else:
            assert isinstance(sp, OpaqueSP)


class TestUserAttributeSubPackets(object):
    def test_load(self, uasubpacket):
        spb = uasubpacket[:]
        sp = UserAttribute(uasubpacket)

        assert uasubpacket == b'\xca\xfe\xba\xbe'
        assert len(sp) == len(spb) - 4
        assert len(sp) == len(bytes(sp))
        assert bytes(sp) == bytes(spb[:-4])

        if sp.header.typeid in _uaspclasses:
            assert sp.__class__.__name__ == _uaspclasses[sp.header.typeid]

        else:
            assert isinstance(sp, OpaqueSP)


class TestString2Key(object):
    def test_simple_string2key(self, sis2k):
        b = sis2k[:]
        s = String2Key()
        s.parse(sis2k)

        assert len(sis2k) == 0
        assert len(s) == len(b)
        assert bytes(s) == bytes(b)

        assert bool(s)
        assert s.halg in HashAlgorithm
        assert s.encalg in SymmetricKeyAlgorithm
        assert s.specifier == String2KeyType.Simple
        assert s.iv == b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'


    def test_salted_string2key(self, sas2k):
        b = sas2k[:]
        s = String2Key()
        s.parse(sas2k)

        assert len(sas2k) == 0
        assert len(s) == len(b)
        assert bytes(s) == bytes(b)

        assert bool(s)
        assert s.halg in HashAlgorithm
        assert s.encalg in SymmetricKeyAlgorithm
        assert s.specifier == String2KeyType.Salted
        assert s.salt == b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE'
        assert s.iv == b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'

    def test_iterated_string2key(self, is2k):
        b = is2k[:]
        s = String2Key()
        s.parse(is2k)

        assert len(is2k) == 0
        assert len(s) == len(b)
        assert bytes(s) == bytes(b)

        assert bool(s)
        assert s.halg in HashAlgorithm
        assert s.encalg in SymmetricKeyAlgorithm
        assert s.specifier == String2KeyType.Iterated
        assert s.salt == b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE'
        assert s.count == 2048
        assert s.iv == b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
